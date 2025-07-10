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
    app,
    load_contract_from_account,
)
from typer.testing import CliRunner

runner = CliRunner()


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
    mock_account.starknet = AsyncMock()
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


@pytest.mark.asyncio
async def test_change_guardian(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "changeGuardian": MagicMock(prepare_invoke_v1=AsyncMock()),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_pub_key = "0x789"
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian(mock_account.starknet, mock_contract, mock_pub_key)
        mock_contract.functions["changeGuardian"].prepare_invoke_v1.assert_called_once()


@pytest.mark.asyncio
async def test_change_guardian_backup(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "changeGuardianBackup": MagicMock(prepare_invoke_v1=AsyncMock()),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_pub_key = "0x789"
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_guardian_backup(mock_account.starknet, mock_contract, mock_pub_key)
        mock_contract.functions["changeGuardianBackup"].prepare_invoke_v1.assert_called_once()


@pytest.mark.asyncio
async def test_change_signer(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "changeGuardian": MagicMock(prepare_invoke_v1=AsyncMock()),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    mock_pub_key = "0x789"
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _change_signer(mock_account.starknet, mock_contract, mock_pub_key)
        mock_contract.functions["changeGuardian"].prepare_invoke_v1.assert_called_once()


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
async def test_withdraw_to_l1(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "withdraw": MagicMock(prepare_invoke_v1=AsyncMock()),
        "initiate_withdraw": MagicMock(prepare_invoke_v1=AsyncMock()),
        "get_version": MagicMock(call=AsyncMock(return_value=MagicMock(version=1))),
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _withdraw_to_l1(mock_account, "0x123", Decimal("10.0"))
        mock_contract.functions["withdraw"].prepare_invoke_v1.assert_called_once()
        mock_contract.functions["initiate_withdraw"].prepare_invoke_v1.assert_called_once()


@pytest.mark.asyncio
async def test_transfer_on_l2(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "withdraw": MagicMock(prepare_invoke_v1=AsyncMock()),
        "increase_allowance": MagicMock(prepare_invoke_v1=AsyncMock()),
        "deposit_on_behalf_of": MagicMock(prepare_invoke_v1=AsyncMock()),
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _transfer_on_l2(mock_account, "0x123", Decimal("10.0"))
        mock_contract.functions["withdraw"].prepare_invoke_v1.assert_called_once()
        mock_contract.functions["increase_allowance"].prepare_invoke_v1.assert_called_once()
        mock_contract.functions["deposit_on_behalf_of"].prepare_invoke_v1.assert_called_once()


@pytest.mark.asyncio
async def test_deposit_to_paraclear(mock_account, setup_env_vars):
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "deposit": MagicMock(prepare_invoke_v1=AsyncMock()),
        "increase_allowance": MagicMock(prepare_invoke_v1=AsyncMock()),
        "get_token_asset_balance": MagicMock(call=AsyncMock(return_value=MagicMock(balance=1000))),
        "getSigner": MagicMock(call=AsyncMock(return_value=MagicMock(signer=0x1))),
        "getGuardian": MagicMock(call=AsyncMock(return_value=MagicMock(guardian=0x2))),
        "getGuardianBackup": MagicMock(call=AsyncMock(return_value=MagicMock(guardianBackup=0x3))),
    }
    with (
        patch("paradex_cli.main.load_contract_from_account", return_value=mock_contract),
        patch("paradex_cli.main.random_max_fee", return_value=1),
        patch("paradex_cli.main._process_invoke", new_callable=AsyncMock),
    ):
        await _deposit_to_paraclear(mock_account, Decimal("10.0"))
        mock_contract.functions["deposit"].prepare_invoke_v1.assert_called_once()
        mock_contract.functions["increase_allowance"].prepare_invoke_v1.assert_called_once()

@pytest.mark.asyncio
async def test_escape_guardian_logic():
    mock_contract = AsyncMock()
    mock_contract.functions = {
        "escapeGuardian": MagicMock(prepare_invoke_v1=MagicMock(return_value="prepared_call"))
    }

    mock_account = MagicMock()
    mock_account.prepare_invoke = AsyncMock(return_value="prepared_invoke")

    with patch("paradex_cli.main._check_multisig_required", return_value=False), \
         patch("paradex_cli.main._process_invoke", new_callable=AsyncMock) as mock_process:

        await _escape_guardian(mock_account, mock_contract, "0xABC")

        mock_contract.functions["escapeGuardian"].prepare_invoke_v1.assert_called_once()
        mock_account.prepare_invoke.assert_called_once_with(calls="prepared_call", max_fee=ANY)
        mock_process.assert_called_once()

def test_check_env_vars_missing():
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("locale.getpreferredencoding", return_value="UTF-8"),
    ):
        result = runner.invoke(app, ["add-guardian-backup", "0x789", "--env", "testnet"])
        assert result.exit_code == 1
        assert "Missing required environment variables" in result.stdout


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
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["add-guardian-backup", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_add_guardian_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["add-guardian", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_change_signer_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock),
        patch("paradex_cli.main.KeyPair.from_private_key", return_value=MagicMock()),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["change-signer", "0x789", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_sign_invoke_tx_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
    ):
        result = runner.invoke(app, ["sign-invoke-tx", "dummy_path", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()


def test_submit_invoke_tx_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
    ):
        result = runner.invoke(
            app,
            ["submit-invoke-tx", "dummy_tx_file", "sig_file1", "sig_file2", "--env", "testnet"],
        )
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()

def test_escape_guardian_command(setup_env_vars):
    with (
        patch("paradex_cli.main.ParadexAccount") as mock_account,
        patch("paradex_cli.main.asyncio.run", new_callable=AsyncMock) as mock_async_run,
        patch("paradex_cli.main.load_contract_from_account", new_callable=AsyncMock),
        patch("builtins.open", new_callable=mock_open),
    ):
        result = runner.invoke(app, ["escape-guardian", "0x123", "--env", "testnet"])
        assert result.exit_code == 0
        mock_account.assert_called_once()
        mock_async_run.assert_called()
