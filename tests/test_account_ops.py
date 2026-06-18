from unittest.mock import AsyncMock, MagicMock

import pytest
from starknet_py.hash.selector import get_selector_from_name

from paradex_cli.account_ops import (
    AccountKind,
    build_change_guardian_backup_call,
    build_change_guardian_call,
    build_escape_guardian_call,
    build_trigger_escape_guardian_call,
    detect_account_kind,
    option_none,
    option_some_starknet_signer,
    read_signers,
)

ACCOUNT = 0x123
PUBKEY = 0x789


def _contract_with_functions(*names, cairo_version=None):
    contract = MagicMock()
    contract.functions = {name: MagicMock() for name in names}
    # By default leave data.cairo_version non-deterministic (MagicMock) so
    # detection falls through to ABI probing; set explicitly to exercise the
    # authoritative on-chain-version path.
    contract.data.cairo_version = cairo_version
    return contract


# --- detection -------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_cairo1_by_get_owner():
    contract = _contract_with_functions("get_owner", "get_guardian")
    assert await detect_account_kind(contract) is AccountKind.CAIRO1


@pytest.mark.asyncio
async def test_detect_cairo1_by_change_guardian():
    contract = _contract_with_functions("change_guardian")
    assert await detect_account_kind(contract) is AccountKind.CAIRO1


@pytest.mark.asyncio
async def test_detect_cairo0_by_getsigner():
    contract = _contract_with_functions("getSigner", "getGuardian", "changeGuardian")
    assert await detect_account_kind(contract) is AccountKind.CAIRO0


@pytest.mark.asyncio
async def test_detect_uses_onchain_cairo_version_v1():
    # On-chain version is authoritative even if the resolved ABI looks Cairo 0
    # (e.g. a stale proxy ABI). cairo_version=1 -> CAIRO1.
    contract = _contract_with_functions("getSigner", "changeGuardian", cairo_version=1)
    assert await detect_account_kind(contract) is AccountKind.CAIRO1


@pytest.mark.asyncio
async def test_detect_uses_onchain_cairo_version_v0():
    contract = _contract_with_functions("get_owner", "change_guardian", cairo_version=0)
    assert await detect_account_kind(contract) is AccountKind.CAIRO0


# --- Option<Signer> serialization (the risky bit) --------------------------


def test_option_some_starknet_signer_layout():
    # Some(Signer::Starknet(pubkey)) -> [Option::Some=0, Signer::Starknet=0, pubkey]
    assert option_some_starknet_signer(PUBKEY) == [0, 0, PUBKEY]


def test_option_none_layout():
    assert option_none() == [1]


# --- Cairo 1 calldata ------------------------------------------------------


def test_change_guardian_cairo1_set():
    call = build_change_guardian_call(AccountKind.CAIRO1, ACCOUNT, PUBKEY)
    assert call.to_addr == ACCOUNT
    assert call.selector == get_selector_from_name("change_guardian")
    assert call.calldata == [0, 0, PUBKEY]


def test_change_guardian_cairo1_remove_uses_none():
    call = build_change_guardian_call(AccountKind.CAIRO1, ACCOUNT, 0)
    assert call.calldata == [1]


def test_change_guardian_backup_cairo1_set():
    call = build_change_guardian_backup_call(AccountKind.CAIRO1, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("change_guardian_backup")
    assert call.calldata == [0, 0, PUBKEY]


def test_escape_guardian_cairo1_takes_no_arg():
    call = build_escape_guardian_call(AccountKind.CAIRO1, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("escape_guardian")
    assert call.calldata == []


def test_trigger_escape_guardian_cairo1_commits_new_guardian():
    call = build_trigger_escape_guardian_call(AccountKind.CAIRO1, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("trigger_escape_guardian")
    assert call.calldata == [0, 0, PUBKEY]


# --- Cairo 0 calldata (back-compat) ----------------------------------------


def test_change_guardian_cairo0_bare_felt():
    call = build_change_guardian_call(AccountKind.CAIRO0, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("changeGuardian")
    assert call.calldata == [PUBKEY]


# --- Cairo 1 multiowner (v0.5.0) guardian calldata --------------------------


def test_change_guardian_multiowner_add():
    call = build_change_guardian_call(AccountKind.CAIRO1_MULTIOWNER, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("change_guardians")
    # change_guardians(remove=[], add=[Signer::Starknet(pk)])
    # [remove_len=0, add_len=1, variant=0, pk]
    assert call.calldata == [0, 1, 0, PUBKEY]


def test_change_guardian_multiowner_remove_with_guids():
    call = build_change_guardian_call(
        AccountKind.CAIRO1_MULTIOWNER, ACCOUNT, 0, remove_guardian_guids=[0xAAA, 0xBBB]
    )
    # remove two guids, add none
    assert call.calldata == [2, 0xAAA, 0xBBB, 0]


def test_change_guardian_backup_rejected_on_multiowner():
    import pytest as _pytest

    with _pytest.raises(ValueError):
        build_change_guardian_backup_call(AccountKind.CAIRO1_MULTIOWNER, ACCOUNT, PUBKEY)


def test_escape_guardian_multiowner_no_arg():
    call = build_escape_guardian_call(AccountKind.CAIRO1_MULTIOWNER, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("escape_guardian")
    assert call.calldata == []


def test_trigger_escape_guardian_multiowner_option():
    call = build_trigger_escape_guardian_call(AccountKind.CAIRO1_MULTIOWNER, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("trigger_escape_guardian")
    assert call.calldata == [0, 0, PUBKEY]


def test_escape_guardian_cairo0_takes_new_guardian():
    call = build_escape_guardian_call(AccountKind.CAIRO0, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("escapeGuardian")
    assert call.calldata == [PUBKEY]


def test_trigger_escape_guardian_cairo0_no_arg():
    call = build_trigger_escape_guardian_call(AccountKind.CAIRO0, ACCOUNT, PUBKEY)
    assert call.selector == get_selector_from_name("triggerEscapeGuardian")
    assert call.calldata == []


# --- read_signers ----------------------------------------------------------


@pytest.mark.asyncio
async def test_read_signers_cairo1():
    contract = MagicMock()
    contract.functions = {
        "get_owner": MagicMock(call=AsyncMock(return_value=[0x1])),
        "get_guardian": MagicMock(call=AsyncMock(return_value=[0x2])),
        "get_guardian_backup": MagicMock(call=AsyncMock(return_value=[0x0])),
    }
    res = await read_signers(contract, AccountKind.CAIRO1)
    assert res == {"owner": 0x1, "guardian": 0x2, "guardian_backup": 0x0}


@pytest.mark.asyncio
async def test_read_signers_cairo0():
    contract = MagicMock()
    contract.functions = {
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(
            call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))
        ),
    }
    res = await read_signers(contract, AccountKind.CAIRO0)
    assert res == {"owner": 0x1, "guardian": 0x2, "guardian_backup": 0x3}
