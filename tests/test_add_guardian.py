import asyncio
import os
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, mock_open, patch, ANY

import pytest
from paradex_cli import (
    _change_guardian,
    _change_guardian_backup,
    _change_signer,
    _deposit_to_paraclear,
    _sign_invoke_tx,
    _submit_invoke_tx,
    _transfer_on_l2,
    _withdraw_to_l1,
    _escape_guardian,
    _sign_register_sub_operator_message,
    app,
    load_contract_from_account,
)
from typer.testing import CliRunner
from starknet_py.hash.selector import get_selector_from_name

runner = CliRunner()


def mock_asyncio_run(coro):
    """Mock asyncio.run that actually executes the coroutine to avoid warnings."""
    if asyncio.iscoroutine(coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    return coro


@pytest.fixture(scope="function")
def setup_env_vars():
    os.environ["PARADEX_ACCOUNT_ADDRESS"] = "0x123"
    os.environ["PARADEX_ACCOUNT_KEY"] = "0x456"
    yield
    os.environ.pop("PARADEX_ACCOUNT_ADDRESS")
    os.environ.pop("PARADEX_ACCOUNT_KEY")


@pytest.fixture(scope="function")
def mock_account():
    mock_account = MagicMock()
    mock_account.l2_address = "0x123"
    mock_starknet = MagicMock()
    mock_starknet.prepare_invoke = AsyncMock()
    mock_starknet.invoke = AsyncMock()
    mock_starknet.signer = MagicMock()
    mock_starknet.signer.sign_transaction = MagicMock(return_value=[1, 2, 3])
    mock_starknet.signer.public_key = 0x123
    mock_starknet.address = 0x123
    mock_account.starknet = mock_starknet
    mock_account.config.paraclear_address = "0x456"
    mock_account.config.paraclear_decimals = 8
    mock_account.config.bridged_tokens = [
        MagicMock(l2_token_address="0x789", decimals=6, l2_bridge_address="0xabc")
    ]
    return mock_account


@pytest.mark.asyncio
async def test_load_contract_from_account(mock_account):
    mock_address = "0x123"
    mock_contract = AsyncMock()
    with patch(
        "paradex_cli.main.Contract.from_address",
        new_callable=AsyncMock,
        return_value=mock_contract,
    ) as mock_from_address:
        contract = await load_contract_from_account(mock_address, mock_account)
        mock_from_address.assert_called_once_with(
            address=mock_address, provider=mock_account.starknet, proxy_config=ANY
        )
        assert contract == mock_contract


def _cairo0_contract():
    """A Cairo 0 Argent account mock: camelCase getters present."""
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.functions = {
        "changeGuardian": MagicMock(prepare_invoke_v3=AsyncMock()),
        "changeGuardianBackup": MagicMock(prepare_invoke_v3=AsyncMock()),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    return mock_contract


@pytest.mark.asyncio
async def test_load_contract_falls_back_on_proxy_resolution_error(mock_account):
    """Cairo 1 (EVM) accounts aren't proxies; proxy resolution must fall back
    to direct ABI loading instead of raising."""
    from starknet_py.proxy.contract_abi_resolver import ProxyResolutionError

    mock_contract = AsyncMock()
    with patch(
        "paradex_cli.main.Contract.from_address",
        new_callable=AsyncMock,
        side_effect=[ProxyResolutionError(proxy_checks=[]), mock_contract],
    ) as mock_from_address:
        contract = await load_contract_from_account("0x123", mock_account)
        assert contract == mock_contract
        # Second (fallback) call must disable proxy resolution.
        assert mock_from_address.call_count == 2
        assert mock_from_address.call_args.kwargs["proxy_config"] is False


@pytest.mark.asyncio
async def test_change_guardian_cairo0(mock_account, setup_env_vars):
    mock_contract = _cairo0_contract()
    mock_pub_key = "0x789"
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian(mock_account.starknet, mock_contract, mock_pub_key)
        # Cairo 0 path: a Call to changeGuardian(felt) is prepared and signed.
        mock_account.starknet.prepare_invoke.assert_called_once()
        call = mock_account.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("changeGuardian")
        assert call.calldata == [0x789]


@pytest.mark.asyncio
async def test_change_guardian_cairo1(mock_account, setup_env_vars):
    # Cairo 1 account: snake_case getters present.
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.functions = {
        "get_owner": MagicMock(call=AsyncMock(return_value=[0x1])),
        "get_guardian": MagicMock(call=AsyncMock(return_value=[0x0])),
        "get_guardian_backup": MagicMock(call=AsyncMock(return_value=[0x0])),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian(mock_account.starknet, mock_contract, "0x789")
        call = mock_account.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("change_guardian")
        # Some(Signer::Starknet(0x789))
        assert call.calldata == [0, 0, 0x789]


@pytest.mark.asyncio
async def test_change_guardian_backup_cairo0(mock_account, setup_env_vars):
    mock_contract = _cairo0_contract()
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian_backup(mock_account.starknet, mock_contract, "0x789")
        call = mock_account.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("changeGuardianBackup")
        assert call.calldata == [0x789]


@pytest.mark.asyncio
async def test_change_guardian_backup_cairo1(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.data.cairo_version = 1
    mock_contract.functions = {
        "get_owner": MagicMock(call=AsyncMock(return_value=[0x1])),
        "get_guardian": MagicMock(call=AsyncMock(return_value=[0x0])),
        "get_guardian_backup": MagicMock(call=AsyncMock(return_value=[0x0])),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian_backup(mock_account.starknet, mock_contract, "0x789")
        call = mock_account.starknet.prepare_invoke.call_args.kwargs["calls"]
        assert call.selector == get_selector_from_name("change_guardian_backup")
        # Some(Signer::Starknet(0x789))
        assert call.calldata == [0, 0, 0x789]


@pytest.mark.asyncio
async def test_change_signer_cairo0(mock_account, setup_env_vars):
    mock_contract = _cairo0_contract()
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_signer(mock_account.starknet, mock_contract, "0x789")
        mock_contract.functions["changeGuardian"].prepare_invoke_v3.assert_called_once()


@pytest.mark.asyncio
async def test_change_signer_cairo1_rejected(mock_account, setup_env_vars):
    import typer

    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.functions = {"get_owner": MagicMock(call=AsyncMock(return_value=[0x1]))}
    with pytest.raises(typer.BadParameter):
        await _change_signer(mock_account.starknet, mock_contract, "0x789")


@pytest.mark.asyncio
async def test_sign_invoke_tx(mock_account, setup_env_vars):
    mock_file_path = "dummy_path"
    mock_invoke = MagicMock()
    with (
        patch("paradex_cli.main.load_invoke", return_value=mock_invoke),
        patch("paradex_cli.main.print_invoke", return_value=None),
        patch("builtins.open", mock_open(read_data="data")),
    ):
        mock_account.starknet.signer.sign_transaction = MagicMock(return_value=[1, 2, 3])
        await _sign_invoke_tx(mock_account, mock_file_path)
        mock_account.starknet.signer.sign_transaction.assert_called_once_with(mock_invoke)


@pytest.mark.asyncio
async def test_submit_invoke_tx(mock_account, setup_env_vars):
    mock_tx_file = "dummy_tx_file"
    mock_sig_files = ["sig_file1", "sig_file2"]
    mock_invoke = MagicMock()
    mock_signature = {"dummy_tx_file": [1, 2, 3], "sig_file1": [4, 5, 6]}
    with (
        patch("paradex_cli.main.load_invoke", return_value=mock_invoke),
        patch(
            "paradex_cli.main.load_signature", side_effect=lambda f: mock_signature.get(f.name, [])
        ),
        patch("paradex_cli.main._fetch_signers_pubkeys", return_value=["0x1", "0x2", "0x3"]),
        patch("paradex_cli.main.load_contract_from_account", return_value=MagicMock()),
        patch("builtins.open", mock_open(read_data="data")),
    ):
        mock_account.starknet.invoke = AsyncMock()
        await _submit_invoke_tx(mock_account, mock_tx_file, mock_sig_files)
        mock_account.starknet.invoke.assert_called_once()


@pytest.mark.asyncio
async def test_withdraw_to_l1_legacy_bridge(mock_account, setup_env_vars):
    # Legacy (v1) single-token bridge on a Cairo 0 account: initiate_withdraw.
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.data.cairo_version = 0  # account is cairo0 -> getSigner path
    mock_contract.functions = {
        "withdraw": MagicMock(prepare_invoke_v3=AsyncMock()),
        "initiate_withdraw": MagicMock(prepare_invoke_v3=AsyncMock()),
        "get_version": MagicMock(call=AsyncMock(return_value=(1,))),  # bridge version 1
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _withdraw_to_l1(mock_account, "0x123", Decimal("10.0"))
        mock_contract.functions["withdraw"].prepare_invoke_v3.assert_called_once()
        mock_contract.functions["initiate_withdraw"].prepare_invoke_v3.assert_called_once()


@pytest.mark.asyncio
async def test_withdraw_to_l1_v2_bridge(mock_account, setup_env_vars):
    # StarkGate v2 bridge: initiate_token_withdraw(l1_token, l1_recipient, amount).
    mock_account.config.bridged_tokens[0].l1_token_address = "0xL1USDC".replace("L1USDC", "29a8")
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.data.cairo_version = 0
    mock_contract.functions = {
        "withdraw": MagicMock(prepare_invoke_v3=AsyncMock()),
        "initiate_token_withdraw": MagicMock(prepare_invoke_v3=AsyncMock()),
        "get_version": MagicMock(call=AsyncMock(return_value=(2,))),  # bridge version 2
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x0))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x0))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _withdraw_to_l1(mock_account, "0x456", Decimal("10.0"))
        mock_contract.functions["withdraw"].prepare_invoke_v3.assert_called_once()
        mock_contract.functions["initiate_token_withdraw"].prepare_invoke_v3.assert_called_once()


@pytest.mark.asyncio
async def test_transfer_on_l2(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "withdraw": MagicMock(prepare_invoke_v3=AsyncMock()),
        "increase_allowance": MagicMock(prepare_invoke_v3=AsyncMock()),
        "deposit_on_behalf_of": MagicMock(prepare_invoke_v3=AsyncMock()),
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _transfer_on_l2(mock_account, "0x123", Decimal("10.0"))
        mock_contract.functions["withdraw"].prepare_invoke_v3.assert_called_once()
        mock_contract.functions["increase_allowance"].prepare_invoke_v3.assert_called_once()
        mock_contract.functions["deposit_on_behalf_of"].prepare_invoke_v3.assert_called_once()


@pytest.mark.asyncio
async def test_deposit_to_paraclear(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "deposit": MagicMock(prepare_invoke_v3=AsyncMock()),
        "increase_allowance": MagicMock(prepare_invoke_v3=AsyncMock()),
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _deposit_to_paraclear(mock_account, Decimal("10.0"))
        mock_contract.functions["deposit"].prepare_invoke_v3.assert_called_once()
        mock_contract.functions["increase_allowance"].prepare_invoke_v3.assert_called_once()


@pytest.mark.asyncio
async def test_escape_guardian_logic_cairo0():
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.functions = {
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }

    mock_account = MagicMock()
    mock_account.prepare_invoke = AsyncMock(return_value="prepared_invoke")

    with patch("paradex_cli.main._process_invoke", new_callable=AsyncMock) as mock_process:
        await _escape_guardian(mock_account, mock_contract, "0xABC")

        call = mock_account.prepare_invoke.call_args.kwargs["calls"]
        # Cairo 0 escapeGuardian(felt) carries the new guardian.
        assert call.selector == get_selector_from_name("escapeGuardian")
        assert call.calldata == [0xABC]
        mock_process.assert_called_once()


@pytest.mark.asyncio
async def test_escape_guardian_logic_cairo1():
    mock_contract = AsyncMock()
    mock_contract.address = 0x123
    mock_contract.functions = {
        "get_owner": MagicMock(call=AsyncMock(return_value=[0x1])),
        "get_guardian": MagicMock(call=AsyncMock(return_value=[0x2])),
        "get_guardian_backup": MagicMock(call=AsyncMock(return_value=[0x0])),
    }

    mock_account = MagicMock()
    mock_account.prepare_invoke = AsyncMock(return_value="prepared_invoke")

    with patch("paradex_cli.main._process_invoke", new_callable=AsyncMock) as mock_process:
        await _escape_guardian(mock_account, mock_contract, "0xABC")

        call = mock_account.prepare_invoke.call_args.kwargs["calls"]
        # Cairo 1 escape_guardian() takes no argument.
        assert call.selector == get_selector_from_name("escape_guardian")
        assert call.calldata == []
        mock_process.assert_called_once()


def test_check_env_vars_missing():
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("locale.getpreferredencoding", return_value="UTF-8"),
    ):
        result = runner.invoke(app, ["add-guardian-backup", "0x789", "--env", "testnet"])
        assert result.exit_code == 1
        assert "Missing required environment variables" in result.output


def test_command_prints_clean_message_on_client_error(setup_env_vars):
    """On-chain failures (ClientError) must surface as a concise stderr message
    and a non-zero exit — not a raw Python traceback."""
    from starknet_py.net.client_errors import ClientError

    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123

    def boom(*_a, **_k):
        raise ClientError(code=41, message="Transaction execution error.")

    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj),
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run),
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, side_effect=boom),
    ):
        result = runner.invoke(app, ["add-guardian", "0x789", "--env", "testnet"])

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Error" in result.output
    assert "Transaction execution error" in result.output


def test_command_prints_clean_message_on_value_error(setup_env_vars):
    """Client-side validation failures (ValueError) must also surface cleanly
    (e.g. guardian-backup attempted on a v0.5.0 multiowner account)."""
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123

    def boom(*_a, **_k):
        raise ValueError("guardian-backup is not supported on Argent v0.5.0 multiowner accounts")

    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj),
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run),
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, side_effect=boom),
    ):
        result = runner.invoke(app, ["add-guardian-backup", "0x789", "--env", "testnet"])

    assert result.exit_code != 0
    assert "Error" in result.output
    assert "not supported" in result.output


def test_print_account_info_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run") as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock),
    ):
        result = runner.invoke(app, ["print-account-info", "0x123", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_add_guardian_backup_command(setup_env_vars):
    mock_contract = MagicMock()
    mock_contract.functions = {
        "changeGuardianBackup": MagicMock(prepare_invoke_v3=MagicMock(return_value=MagicMock())),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123
    mock_account_obj.starknet.prepare_invoke = AsyncMock(return_value=MagicMock())
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, return_value=mock_contract),
        patch("paradex_cli.main._check_multisig_required", new_callable=AsyncMock, return_value=False),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["add-guardian-backup", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_add_guardian_command(setup_env_vars):
    mock_contract = MagicMock()
    mock_contract.functions = {
        "changeGuardian": MagicMock(prepare_invoke_v3=MagicMock(return_value=MagicMock())),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123
    mock_account_obj.starknet.prepare_invoke = AsyncMock(return_value=MagicMock())
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, return_value=mock_contract),
        patch("paradex_cli.main._check_multisig_required", new_callable=AsyncMock, return_value=False),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["add-guardian", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_change_signer_command(setup_env_vars):
    mock_contract = MagicMock()
    mock_contract.functions = {
        "changeGuardian": MagicMock(prepare_invoke_v3=MagicMock(return_value=MagicMock())),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123
    mock_account_obj.starknet.prepare_invoke = AsyncMock(return_value=MagicMock())
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, return_value=mock_contract),
        patch("paradex_cli.main._check_multisig_required", new_callable=AsyncMock, return_value=False),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["change-signer", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_sign_invoke_tx_command(setup_env_vars):
    mock_invoke = MagicMock()
    mock_account_obj = MagicMock()
    mock_account_obj.starknet.signer.sign_transaction = MagicMock(return_value=[1, 2, 3])
    mock_account_obj.starknet.signer.public_key = 0x123
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_invoke", return_value=mock_invoke),
        patch("paradex_cli.main.print_invoke"),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["sign-invoke-tx", "dummy_path", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_submit_invoke_tx_command(setup_env_vars):
    mock_invoke = MagicMock()
    mock_contract = MagicMock()
    mock_contract.address = 0x123
    mock_contract.functions = {
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123
    mock_account_obj.starknet.invoke = AsyncMock(return_value=MagicMock(hash=0x456, wait_for_acceptance=AsyncMock()))
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_invoke", return_value=mock_invoke),
        patch("paradex_cli.main.load_signature", return_value={"0x1": [1, 2, 3]}),
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, return_value=mock_contract),
        patch("paradex_cli.main._fetch_signers_pubkeys", new_callable=AsyncMock, return_value=["0x1", "0x2", "0x3"]),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(
            app,
            ["submit-invoke-tx", "dummy_tx_file", "sig_file1", "sig_file2", "--env", "testnet"],
        )
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_escape_guardian_command(setup_env_vars):
    mock_contract = MagicMock()
    mock_contract.functions = {
        "escapeGuardian": MagicMock(prepare_invoke_v3=MagicMock(return_value=MagicMock())),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_account_obj = MagicMock()
    mock_account_obj.l2_address = 0x123
    mock_account_obj.starknet.prepare_invoke = AsyncMock(return_value=MagicMock())
    
    with (
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj) as mock_account,
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock, return_value=mock_contract),
        patch("paradex_cli.main._check_multisig_required", new_callable=AsyncMock, return_value=False),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["escape-guardian", "0x123", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


VAULT_ADDRESS = "0xaabbcc"
SUB_OPERATOR_ADDRESS = "0xddeeff"
MOCK_NONCE = 7
MOCK_SIGNATURE = [111, 222]


@pytest.mark.asyncio
async def test_sign_register_sub_operator_message(mock_account, setup_env_vars):
    """Unit-test the async signing helper."""
    mock_account.starknet.client.call_contract = AsyncMock(return_value=[MOCK_NONCE])
    mock_account.starknet.sign_message = MagicMock(return_value=MOCK_SIGNATURE)
    mock_account.config.starknet_chain_id = "0x5354524b4e45545f54455354"

    with (
        patch("paradex_cli.main.Paradex") as mock_paradex_cls,
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account),
        patch("paradex_cli.main.time") as mock_time,
    ):
        mock_paradex_cls.return_value.config.starknet_chain_id = (
            mock_account.config.starknet_chain_id
        )
        mock_time.time.return_value = 1_000_000.0  # fixed timestamp for determinism

        await _sign_register_sub_operator_message(
            VAULT_ADDRESS, SUB_OPERATOR_ADDRESS, "testnet"
        )

    mock_account.starknet.client.call_contract.assert_awaited_once()
    call_arg = mock_account.starknet.client.call_contract.call_args[1]["call"]
    assert call_arg.calldata == [int(SUB_OPERATOR_ADDRESS, 16)]
    mock_account.starknet.sign_message.assert_called_once()


@pytest.mark.asyncio
async def test_sign_register_sub_operator_message_invalid_env(mock_account, setup_env_vars):
    """Unsupported environment must exit with a non-zero code."""
    import typer

    with pytest.raises(typer.Exit):
        await _sign_register_sub_operator_message(
            VAULT_ADDRESS, SUB_OPERATOR_ADDRESS, "unknown_env"
        )


def test_sign_register_sub_operator_message_command(setup_env_vars):
    """CLI smoke-test: command wires args correctly and exits 0."""
    mock_account_obj = MagicMock()
    mock_account_obj.starknet.client.call_contract = AsyncMock(return_value=[MOCK_NONCE])
    mock_account_obj.starknet.sign_message = MagicMock(return_value=MOCK_SIGNATURE)
    mock_account_obj.config.starknet_chain_id = "0x5354524b4e45545f54455354"

    with (
        patch("paradex_cli.main.Paradex") as mock_paradex_cls,
        patch("paradex_cli.main.ParadexAccount", return_value=mock_account_obj),
        patch("paradex_cli.main.asyncio.run", side_effect=mock_asyncio_run),
        patch("paradex_cli.main.time") as mock_time,
    ):
        mock_paradex_cls.return_value.config.starknet_chain_id = (
            mock_account_obj.config.starknet_chain_id
        )
        mock_time.time.return_value = 1_000_000.0

        result = runner.invoke(
            app,
            [
                "sign-register-sub-operator-message",
                VAULT_ADDRESS,
                SUB_OPERATOR_ADDRESS,
                "--env",
                "testnet",
            ],
        )

    assert result.exit_code == 0
    assert "Nonce:" in result.output
    assert "Expiry:" in result.output
    assert "Signature:" in result.output
