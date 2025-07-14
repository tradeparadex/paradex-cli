"""
Comprehensive tests for the multisig CLI commands.

This test module covers:
- Async functions: _change_threshold, _add_signers, _remove_signers, _replace_signer,
  _get_multisig_info, _is_signer, _verify_signature, _sign_transaction_from_file,
  _submit_transaction, _merge_signatures
- CLI commands: change-threshold, add-signers, remove-signers, replace-signer,
  get-info, is-signer, verify-signature, sign-transaction, merge-signatures, submit-transaction
- Helper functions: get_multisig_contract, format_tx_for_signing, create_invoke_tx_from_json
- Error cases: insufficient signers, invalid signatures, missing files
"""
import os
import json
import tempfile
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
from typer.testing import CliRunner

from paradex_cli.multisig import (
    _change_threshold,
    _add_signers,
    _remove_signers,
    _replace_signer,
    _get_multisig_info,
    _is_signer,
    _verify_signature,
    _sign_transaction_from_file,
    _submit_transaction,
    _merge_signatures,
    get_multisig_contract,
    format_tx_for_signing,
    create_invoke_tx_from_json,
    multisig_app,
)

runner = CliRunner()


@pytest.fixture(scope="function")
def setup_env_vars():
    os.environ["TESTNET_ACCOUNT_ADDRESS"] = "0x123"
    os.environ["TESTNET_ACCOUNT_KEY"] = "0x456"
    yield
    os.environ.pop("TESTNET_ACCOUNT_ADDRESS", None)
    os.environ.pop("TESTNET_ACCOUNT_KEY", None)


@pytest.fixture
def mock_config():
    config = MagicMock()
    config.account_address = "0x123"
    config.account_private_key = "0x456"
    config.client = AsyncMock()
    config.env = "testnet"
    return config


@pytest.fixture
def mock_multisig_contract():
    contract = AsyncMock()
    contract.address = 0x789
    contract.functions = {
        "change_threshold": MagicMock(prepare_invoke_v1=AsyncMock()),
        "add_signers": MagicMock(prepare_invoke_v1=AsyncMock()),
        "remove_signers": MagicMock(prepare_invoke_v1=AsyncMock()),
        "replace_signer": MagicMock(prepare_invoke_v1=AsyncMock()),
        "get_name": MagicMock(call=AsyncMock(return_value=(0x4d756c74697369672c,))),  # "Multisig" encoded
        "get_version": MagicMock(call=AsyncMock(return_value=({"major": 1, "minor": 0, "patch": 0},))),
        "get_threshold": MagicMock(call=AsyncMock(return_value=(2,))),
        "get_signers": MagicMock(call=AsyncMock(return_value=([0x111, 0x222, 0x333],))),
        "is_signer": MagicMock(call=AsyncMock(return_value=True)),
        "is_valid_signer_signature": MagicMock(call=AsyncMock(return_value=True)),
    }
    return contract


@pytest.fixture
def mock_account():
    account = AsyncMock()
    account.address = 0x123
    account.signer = MagicMock()
    account.signer.public_key = 0x111
    account.signer.sign_transaction = MagicMock(return_value=[0x1, 0x2])
    account._chain_id = 0x534e5f5345504f4c4941
    account.prepare_invoke = AsyncMock(return_value=MagicMock(calculate_hash=MagicMock(return_value=0xabc)))
    account.invoke = AsyncMock(return_value=MagicMock(hash=0xdef))
    account.client = AsyncMock()
    account.client.wait_for_tx = AsyncMock()
    return account


# Tests for async functions
@pytest.mark.asyncio
async def test_get_multisig_contract():
    mock_config = MagicMock()
    mock_config.client = AsyncMock()
    mock_contract = AsyncMock()

    with patch("paradex_cli.multisig.Contract.from_address", new_callable=AsyncMock, return_value=mock_contract):
        contract = await get_multisig_contract(mock_config, "0x789")
        assert contract == mock_contract


@pytest.mark.asyncio
async def test_change_threshold(mock_config, mock_multisig_contract, mock_account):
    with (
        patch("paradex_cli.multisig.state.load_account", new_callable=AsyncMock, return_value=mock_account),
        patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract),
    ):
        await _change_threshold(mock_config, "0x789", 3)

        mock_multisig_contract.functions["change_threshold"].prepare_invoke_v1.assert_called_once_with(new_threshold=3)
        mock_account.prepare_invoke.assert_called_once()
        mock_account.invoke.assert_called_once()


@pytest.mark.asyncio
async def test_add_signers(mock_config, mock_multisig_contract, mock_account):
    signers_to_add = [0x444, 0x555]

    with (
        patch("paradex_cli.multisig.state.load_account", new_callable=AsyncMock, return_value=mock_account),
        patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract),
    ):
        await _add_signers(mock_config, "0x789", 4, signers_to_add)

        mock_multisig_contract.functions["add_signers"].prepare_invoke_v1.assert_called_once_with(
            new_threshold=4, signers_to_add=signers_to_add
        )
        mock_account.prepare_invoke.assert_called_once()
        mock_account.invoke.assert_called_once()


@pytest.mark.asyncio
async def test_remove_signers(mock_config, mock_multisig_contract, mock_account):
    signers_to_remove = [0x333]

    with (
        patch("paradex_cli.multisig.state.load_account", new_callable=AsyncMock, return_value=mock_account),
        patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract),
    ):
        await _remove_signers(mock_config, "0x789", 2, signers_to_remove)

        mock_multisig_contract.functions["remove_signers"].prepare_invoke_v1.assert_called_once_with(
            new_threshold=2, signers_to_remove=signers_to_remove
        )
        mock_account.prepare_invoke.assert_called_once()


@pytest.mark.asyncio
async def test_replace_signer(mock_config, mock_multisig_contract, mock_account):
    with (
        patch("paradex_cli.multisig.state.load_account", new_callable=AsyncMock, return_value=mock_account),
        patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract),
    ):
        await _replace_signer(mock_config, "0x789", 0x333, 0x444)

        mock_multisig_contract.functions["replace_signer"].prepare_invoke_v1.assert_called_once_with(
            signer_to_remove=0x333, signer_to_add=0x444
        )
        mock_account.prepare_invoke.assert_called_once()


@pytest.mark.asyncio
async def test_get_multisig_info(mock_config, mock_multisig_contract, capsys):
    with patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract):
        await _get_multisig_info(mock_config, "0x789")

        captured = capsys.readouterr()
        assert "Multisig Name:" in captured.out
        assert "Version: 1.0.0" in captured.out
        assert "Threshold: 2" in captured.out
        assert "Signers (3):" in captured.out


@pytest.mark.asyncio
async def test_is_signer_true(mock_config, mock_multisig_contract, capsys):
    with patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract):
        await _is_signer(mock_config, "0x789", 0x111)

        captured = capsys.readouterr()
        assert "✅" in captured.out
        assert "is a signer" in captured.out


@pytest.mark.asyncio
async def test_is_signer_false(mock_config, mock_multisig_contract, capsys):
    mock_multisig_contract.functions["is_signer"].call = AsyncMock(return_value=False)

    with patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract):
        await _is_signer(mock_config, "0x789", 0x999)

        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "is NOT a signer" in captured.out


@pytest.mark.asyncio
async def test_verify_signature_valid(mock_config, mock_multisig_contract, capsys):
    with patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract):
        await _verify_signature(mock_config, "0x789", 0xabc, 0x111, 0x1, 0x2)

        captured = capsys.readouterr()
        assert "✅ The signature is valid" in captured.out


@pytest.mark.asyncio
async def test_verify_signature_invalid(mock_config, mock_multisig_contract, capsys):
    mock_multisig_contract.functions["is_valid_signer_signature"].call = AsyncMock(return_value=False)

    with patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract):
        await _verify_signature(mock_config, "0x789", 0xabc, 0x111, 0x1, 0x2)

        captured = capsys.readouterr()
        assert "❌ The signature is NOT valid" in captured.out


@pytest.mark.asyncio
async def test_sign_transaction_from_file(mock_config, mock_account):
    tx_data = {
        "transaction": {
            "maxFee": "0x100",
            "version": "0x1",
            "nonce": "0x1",
            "calls": []
        },
        "multisigAddress": "0x789"
    }

    with (
        patch("paradex_cli.multisig.state.load_account", new_callable=AsyncMock, return_value=mock_account),
        patch("builtins.open", mock_open(read_data=json.dumps(tx_data))),
        patch("paradex_cli.multisig.create_invoke_tx_from_json") as mock_create_invoke,
    ):
        mock_invoke = MagicMock()
        mock_invoke.calculate_hash = MagicMock(return_value=0xabc)
        mock_create_invoke.return_value = mock_invoke

        result = await _sign_transaction_from_file(mock_config, "test.json")

        assert result["signer"] == hex(mock_account.signer.public_key)
        assert "starknetSignature" in result
        mock_account.signer.sign_transaction.assert_called_once_with(mock_invoke)


@pytest.mark.asyncio
async def test_submit_transaction_insufficient_signers(mock_config, capsys):
    tx_data = {
        "multisigAddress": "0x789",
        "transaction": {},
        "approvedSigners": ["0x111"],  # Only 1 signer, but threshold is 2
        "signatures": {}
    }

    mock_multisig_contract = AsyncMock()
    mock_multisig_contract.functions = {
        "get_threshold": MagicMock(call=AsyncMock(return_value=(2,)))
    }

    with (
        patch("builtins.open", mock_open(read_data=json.dumps(tx_data))),
        patch("paradex_cli.multisig.get_multisig_contract", new_callable=AsyncMock, return_value=mock_multisig_contract),
    ):
        await _submit_transaction(mock_config, "test.json")

        captured = capsys.readouterr()
        assert "❌ Not enough signers have approved" in captured.out


@pytest.mark.asyncio
async def test_merge_signatures():
    tx_data = {
        "transaction": {"maxFee": "0x100"},
        "multisigAddress": "0x789"
    }

    sig_data1 = {
        "signer": "0x111",
        "starknetSignature": {"r": "0x1", "s": "0x2"}
    }

    sig_data2 = {
        "signer": "0x222",
        "starknetSignature": {"r": "0x3", "s": "0x4"}
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        tx_file = os.path.join(temp_dir, "tx.json")
        sig_file1 = os.path.join(temp_dir, "sig1.json")
        sig_file2 = os.path.join(temp_dir, "sig2.json")
        output_file = os.path.join(temp_dir, "merged.json")

        with open(tx_file, "w") as f:
            json.dump(tx_data, f)
        with open(sig_file1, "w") as f:
            json.dump(sig_data1, f)
        with open(sig_file2, "w") as f:
            json.dump(sig_data2, f)

        await _merge_signatures(None, tx_file, [sig_file1, sig_file2], output_file)

        # Check the merged file
        with open(output_file) as f:
            merged_data = json.load(f)

        assert merged_data["multisigAddress"] == "0x789"
        assert len(merged_data["approvedSigners"]) == 2
        assert "0x111" in merged_data["approvedSigners"]
        assert "0x222" in merged_data["approvedSigners"]
        assert len(merged_data["signatures"]) == 2


# Test helper functions
def test_format_tx_for_signing():
    from starknet_py.net.client_models import Call
    from starknet_py.net.models.transaction import InvokeV1

    calls = [Call(to_addr=0x123, selector=0x456, calldata=[0x789])]
    invoke_tx = InvokeV1(
        calldata=[0x789],
        max_fee=0x100,
        version=1,
        nonce=1,
        sender_address=0xabc,
        signature=[]
    )
    creator_signer = 0x111
    signature = [0x1, 0x2]

    result = format_tx_for_signing(calls, invoke_tx, creator_signer, signature)

    parsed = json.loads(result)
    assert parsed["creator"] == hex(creator_signer)
    assert parsed["multisigAddress"] == hex(invoke_tx.sender_address)
    assert parsed["starknetSignature"]["r"] == hex(signature[0])
    assert parsed["starknetSignature"]["s"] == hex(signature[1])
    assert len(parsed["transaction"]["calls"]) == 1


def test_create_invoke_tx_from_json():
    tx_data = {
        "transaction": {
            "maxFee": "0x100",
            "version": "0x1",
            "nonce": "0x5",
            "calls": [
                {
                    "contractAddress": "0x123",
                    "entrypoint": "0x456",
                    "calldata": ["0x789"]
                }
            ]
        },
        "multisigAddress": "0xabc"
    }

    invoke_tx = create_invoke_tx_from_json(tx_data)

    assert invoke_tx.max_fee == 0x100
    assert invoke_tx.version == 1
    assert invoke_tx.nonce == 5
    assert invoke_tx.sender_address == 0xabc
    assert len(invoke_tx.calldata) > 0


# CLI Command Tests
def test_change_threshold_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, ["change-threshold", "0x789", "3", "--env", "testnet"])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_add_signers_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, [
            "add-signers", "0x789", "4", "0x111,0x222", "--env", "testnet"
        ])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_remove_signers_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, [
            "remove-signers", "0x789", "2", "0x333", "--env", "testnet"
        ])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_replace_signer_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, [
            "replace-signer", "0x789", "0x333", "0x444", "--env", "testnet"
        ])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_get_info_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, ["get-info", "0x789", "--env", "testnet"])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_is_signer_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, ["is-signer", "0x789", "0x111", "--env", "testnet"])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_verify_signature_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, [
            "verify-signature", "0x789", "0xabc", "0x111", "0x1", "0x2", "--env", "testnet"
        ])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_sign_transaction_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, ["sign-transaction", "test.json", "--env", "testnet"])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_merge_signatures_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, [
            "merge-signatures", "tx.json", "sig1.json,sig2.json", "merged.json", "--env", "testnet"
        ])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()


def test_submit_transaction_command(setup_env_vars):
    with (
        patch("paradex_cli.multisig.state.get_config") as mock_get_config,
        patch("paradex_cli.multisig.asyncio.run") as mock_async_run,
    ):
        result = runner.invoke(multisig_app, ["submit-transaction", "merged.json", "--env", "testnet"])

        assert result.exit_code == 0
        mock_async_run.assert_called_once()
