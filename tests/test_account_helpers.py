"""Tests for version-aware account helpers in paradex_cli.main that were not
covered by the command-level smoke tests: multisig detection, the escape-trigger
guardrails, account-info labelling, and the multisig file-output branch of
_process_invoke.
"""

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
import typer
from starknet_py.hash.selector import get_selector_from_name

from paradex_cli.main import (
    _check_multisig_required,
    _fetch_signers_pubkeys,
    _print_account_info,
    _process_invoke,
    _trigger_escape_guardian,
)


def _cairo1_contract(owner=0x1, guardian=0x0, guardian_backup=0x0):
    contract = MagicMock()
    contract.address = 0x123
    contract.data.cairo_version = 1
    contract.functions = {
        "get_owner": MagicMock(call=AsyncMock(return_value=[owner])),
        "get_guardian": MagicMock(call=AsyncMock(return_value=[guardian])),
        "get_guardian_backup": MagicMock(call=AsyncMock(return_value=[guardian_backup])),
    }
    return contract


def _cairo0_contract(signer=0x1, guardian=0x0, guardian_backup=0x0):
    contract = MagicMock()
    contract.address = 0x123
    contract.data.cairo_version = 0
    contract.functions = {
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=signer))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=guardian))),
        "getGuardianBackup": MagicMock(
            call=AsyncMock(return_value=MagicMock(guardianBackup=guardian_backup))
        ),
    }
    return contract


# --- _check_multisig_required ---------------------------------------------


@pytest.mark.asyncio
async def test_check_multisig_false_when_no_guardian():
    assert await _check_multisig_required(_cairo1_contract(guardian=0, guardian_backup=0)) is False


@pytest.mark.asyncio
async def test_check_multisig_true_when_guardian_set():
    assert await _check_multisig_required(_cairo1_contract(guardian=0x9)) is True


@pytest.mark.asyncio
async def test_check_multisig_true_when_only_backup_set():
    assert await _check_multisig_required(_cairo0_contract(guardian=0, guardian_backup=0x9)) is True


# --- _process_invoke multisig (file-output) branch -------------------------


@pytest.mark.asyncio
async def test_process_invoke_single_sig_invokes_directly():
    saccount = MagicMock()
    saccount.signer.sign_transaction = MagicMock(return_value=[1, 2, 3])
    saccount.invoke = AsyncMock(return_value=MagicMock(hash=0xABC))
    # _process_invoke now polls status via _wait_for_tx until terminal.
    saccount.client.get_transaction_status = AsyncMock(
        return_value=MagicMock(execution_status="TransactionExecutionStatus.SUCCEEDED")
    )
    contract = MagicMock()
    await _process_invoke(saccount, contract, False, MagicMock(), "op")
    saccount.invoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_invoke_multisig_writes_file_and_skips_invoke():
    saccount = MagicMock()
    saccount.invoke = AsyncMock()
    contract = MagicMock()
    m = mock_open()
    with patch("builtins.open", m), patch("paradex_cli.main.print_invoke") as mock_print:
        await _process_invoke(saccount, contract, True, MagicMock(), "withdrawToL1")
        # Multisig path must NOT submit; it writes the prepared invoke to a file.
        saccount.invoke.assert_not_called()
        m.assert_called_once_with("withdrawToL1.json", "w")
        mock_print.assert_called_once()


# --- _print_account_info labelling ----------------------------------------


@pytest.mark.asyncio
async def test_print_account_info_cairo1_labels_owner(capsys):
    await _print_account_info(_cairo1_contract(owner=0x1, guardian=0x2, guardian_backup=0x3))
    out = capsys.readouterr().out
    assert "Account type: cairo1" in out
    assert "Current owner pubkey: 0x1" in out
    assert "Current guardian pubkey: 0x2" in out
    assert "Current guardian backup pubkey: 0x3" in out


@pytest.mark.asyncio
async def test_print_account_info_cairo0_labels_signer(capsys):
    await _print_account_info(_cairo0_contract(signer=0x1))
    out = capsys.readouterr().out
    assert "Account type: cairo0" in out
    assert "Current signer pubkey: 0x1" in out


# --- _fetch_signers_pubkeys ------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_signers_pubkeys_cairo1():
    res = await _fetch_signers_pubkeys(_cairo1_contract(owner=0x1, guardian=0x2, guardian_backup=0x3))
    assert res == ["0x1", "0x2", "0x3"]


@pytest.mark.asyncio
async def test_fetch_signers_pubkeys_cairo0():
    res = await _fetch_signers_pubkeys(_cairo0_contract(signer=0x4, guardian=0x5, guardian_backup=0x6))
    assert res == ["0x4", "0x5", "0x6"]


# --- _trigger_escape_guardian ---------------------------------------------


@pytest.mark.asyncio
async def test_trigger_escape_cairo1_requires_pubkey():
    paccount = MagicMock()
    paccount.l2_address = 0x123
    contract = _cairo1_contract()
    with patch("paradex_cli.main.load_contract_from_account", AsyncMock(return_value=contract)):
        with pytest.raises(typer.BadParameter):
            # default "0x0" -> rejected on Cairo 1
            await _trigger_escape_guardian(paccount, "0x0")


@pytest.mark.asyncio
async def test_trigger_escape_cairo1_commits_new_guardian():
    paccount = MagicMock()
    paccount.l2_address = 0x123
    paccount.starknet.prepare_invoke = AsyncMock(return_value="prepared")
    contract = _cairo1_contract()
    with (
        patch("paradex_cli.main.load_contract_from_account", AsyncMock(return_value=contract)),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _trigger_escape_guardian(paccount, "0x789")
        call = paccount.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("trigger_escape_guardian")
        assert call.calldata == [0, 0, 0x789]


@pytest.mark.asyncio
async def test_trigger_escape_cairo0_no_arg_needed():
    paccount = MagicMock()
    paccount.l2_address = 0x123
    paccount.starknet.prepare_invoke = AsyncMock(return_value="prepared")
    contract = _cairo0_contract()
    with (
        patch("paradex_cli.main.load_contract_from_account", AsyncMock(return_value=contract)),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _trigger_escape_guardian(paccount)  # default "0x0" is fine on Cairo 0
        call = paccount.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("triggerEscapeGuardian")
        assert call.calldata == []
