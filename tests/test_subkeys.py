import os
from unittest.mock import MagicMock, patch

import pytest
from starknet_py.hash.utils import compute_hash_on_elements, message_signature
from typer.testing import CliRunner

from paradex_cli import app
from paradex_cli.subkeys import (
    _to_int,
    build_evm_register_payload,
    build_register_payload,
    build_registration_signature,
    eth_address_from_private_key,
    evm_onboard_and_auth,
    evm_siwe_defaults,
    evm_uncompressed_pubkey,
    SIWE_SUBKEY_STATEMENT_PREFIX,
)

# Throwaway EVM key (anvil dev key #1) — test fixtures only, never funded.
EVM_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

runner = CliRunner()

ACCOUNT = "0x123"
KEY = "0x456"
SUBKEY = "0x789"


@pytest.fixture(scope="function")
def setup_env_vars():
    os.environ["PARADEX_ACCOUNT_ADDRESS"] = ACCOUNT
    os.environ["PARADEX_ACCOUNT_KEY"] = KEY
    yield
    os.environ.pop("PARADEX_ACCOUNT_ADDRESS")
    os.environ.pop("PARADEX_ACCOUNT_KEY")


# --- _to_int ---------------------------------------------------------------


def test_to_int_hex():
    assert _to_int("0x1a") == 26


def test_to_int_decimal_string():
    assert _to_int("26") == 26


def test_to_int_passthrough():
    assert _to_int(26) == 26


# --- signing / payload (pure) ----------------------------------------------


def test_registration_signature_matches_backend_hash():
    ts, expiry = 1_700_000_000, 1_700_000_300
    priv = int(KEY, 16)
    sig = build_registration_signature(ACCOUNT, SUBKEY, priv, ts, expiry)

    # Independently reconstruct the hash the backend verifies and check [r, s].
    expected_hash = compute_hash_on_elements(
        [int(ACCOUNT, 16), int(SUBKEY, 16), ts, expiry]
    )
    r, s = message_signature(expected_hash, priv)
    assert sig == [hex(r), hex(s)]


def test_register_payload_unsigned():
    payload = build_register_payload(SUBKEY, "bot")
    assert payload == {"public_key": SUBKEY, "name": "bot", "state": "active"}
    assert "signature" not in payload


def test_register_payload_signed_includes_window():
    payload = build_register_payload(
        SUBKEY,
        "bot",
        account_address=ACCOUNT,
        private_key=int(KEY, 16),
        sign=True,
        now=1_700_000_000,
        validity_seconds=300,
    )
    assert payload["public_key"] == SUBKEY
    assert payload["signature_timestamp"] == 1_700_000_000
    assert payload["signature_expiry"] == 1_700_000_300
    assert len(payload["signature"]) == 2


def test_register_payload_signed_requires_credentials():
    with pytest.raises(ValueError):
        build_register_payload(SUBKEY, "bot", sign=True)


# --- EVM (SIWE) registration ----------------------------------------------


def test_evm_siwe_defaults_known_envs():
    assert evm_siwe_defaults("testnet") == ("app.testnet.paradex.trade", 11155111)
    assert evm_siwe_defaults("nightly") == ("app.nightly.paradex.trade", 11155111)
    assert evm_siwe_defaults("prod") == ("app.paradex.trade", 1)


def test_evm_siwe_defaults_unknown_env_raises():
    with pytest.raises(ValueError):
        evm_siwe_defaults("local")


def test_build_evm_register_payload_fields():
    payload = build_evm_register_payload(
        SUBKEY,
        "bot",
        eth_private_key=EVM_KEY,
        siwe_domain="app.testnet.paradex.trade",
        chain_id=11155111,
        nonce="abcdef0123456789",
    )
    assert payload["public_key"] == SUBKEY
    assert payload["state"] == "active"
    # EVM auth uses SIWE fields, NOT the stark-curve signature fields.
    assert "siwe_message" in payload and "evm_signature" in payload
    assert "signature" not in payload
    # 65-byte personal_sign signature.
    assert len(bytes.fromhex(payload["evm_signature"][2:])) == 65


def test_build_evm_register_payload_statement_binds_lowercased_subkey():
    mixed = "0xABCdef123"
    payload = build_evm_register_payload(
        mixed,
        "bot",
        eth_private_key=EVM_KEY,
        siwe_domain="app.testnet.paradex.trade",
        chain_id=11155111,
        nonce="abcdef0123456789",
    )
    assert SIWE_SUBKEY_STATEMENT_PREFIX + mixed.lower() in payload["siwe_message"]


def test_evm_register_signature_recovers_to_account_address():
    """The SIWE signature must recover to the account's Ethereum address —
    the exact check the backend's verifyRegisterSubkeySignatureEvm performs."""
    from siwe import SiweMessage

    payload = build_evm_register_payload(
        SUBKEY,
        "bot",
        eth_private_key=EVM_KEY,
        siwe_domain="app.testnet.paradex.trade",
        chain_id=11155111,
        nonce="abcdef0123456789",
    )
    msg = SiweMessage.from_message(payload["siwe_message"])
    # raises siwe.VerificationError if the signature does not recover to address
    msg.verify(payload["evm_signature"])
    assert msg.address == eth_address_from_private_key(EVM_KEY)


def test_evm_uncompressed_pubkey_format():
    pub = evm_uncompressed_pubkey(EVM_KEY)
    assert pub.startswith("0x04")
    assert len(pub) == 2 + 2 + 128  # 0x + 04 + 128 hex


def test_evm_onboard_and_auth_flow():
    """Onboard+auth uses GET /onboarding, POST /v2/onboarding (when not
    existing), then POST /v2/auth, returning the address + jwt."""
    posts = []

    def http_get(path, params):
        assert path == "onboarding"
        assert params["account_signer_type"] == "eip191"
        return {"address": "0xparadex", "exists": False}

    def http_post(path, headers, json_body):
        posts.append((path, headers, json_body))
        # every call must carry the SIWE auth headers
        assert set(["PARADEX-STARKNET-ACCOUNT", "PARADEX-EVM-SIGNATURE", "PARADEX-SIWE-MESSAGE"]).issubset(headers)
        if path == "v2/auth":
            return {"jwt_token": "JWT123"}
        return {}

    addr, jwt = evm_onboard_and_auth(
        http_post, http_get, EVM_KEY, "app.testnet.paradex.trade", 11155111
    )
    assert addr == "0xparadex"
    assert jwt == "JWT123"
    paths = [p[0] for p in posts]
    assert paths == ["v2/onboarding", "v2/auth"]


def test_evm_onboard_and_auth_skips_onboarding_when_exists():
    posts = []

    def http_get(path, params):
        return {"address": "0xparadex", "exists": True}

    def http_post(path, headers, json_body):
        posts.append(path)
        return {"jwt_token": "JWT"} if path == "v2/auth" else {}

    evm_onboard_and_auth(http_post, http_get, EVM_KEY, "app.testnet.paradex.trade", 11155111)
    # already onboarded -> only auth, no onboarding POST
    assert posts == ["v2/auth"]


# --- CLI commands (smoke) --------------------------------------------------


def _mock_authed_paradex():
    pclient = MagicMock()
    pclient.api_client.api_url = "https://api.testnet.paradex.trade/v1"
    pclient.api_client.post = MagicMock(return_value={})
    pclient.api_client.get = MagicMock(return_value={"results": []})
    pclient.api_client.delete = MagicMock(return_value={"public_key": SUBKEY})
    pclient.api_client.put = MagicMock(return_value={})
    return pclient


def test_authed_paradex_uses_valid_constructor_kwargs(setup_env_vars):
    """Guard against passing kwargs Paradex.__init__ doesn't accept.

    The command tests patch _authed_paradex wholesale, so they never exercise
    the real Paradex(...) call; this test does, with Paradex mocked, and would
    have caught the l2_address regression.
    """
    import inspect

    from paradex_py.paradex import Paradex as RealParadex

    import paradex_cli.main as main

    valid_params = set(inspect.signature(RealParadex.__init__).parameters) - {"self"}

    valid_init_params = set(
        inspect.signature(RealParadex.init_account).parameters
    ) - {"self"}

    with patch("paradex_cli.main.Paradex") as mock_paradex:
        client = main._authed_paradex("testnet")

    assert mock_paradex.call_count == 1
    _, kwargs = mock_paradex.call_args
    assert set(kwargs).issubset(valid_params), (
        f"Paradex called with unknown kwargs: {set(kwargs) - valid_params}"
    )
    assert kwargs["env"] == "testnet"

    # Must explicitly initialise the account (onboard + auth) with valid kwargs,
    # otherwise no JWT is set and the private subkey endpoints reject the call.
    client.init_account.assert_called_once()
    _, init_kwargs = client.init_account.call_args
    assert set(init_kwargs).issubset(valid_init_params), (
        f"init_account called with unknown kwargs: {set(init_kwargs) - valid_init_params}"
    )
    assert init_kwargs["l1_address"] == "0x0"


def test_register_subkey_command(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(
            app, ["register-subkey", SUBKEY, "--name", "bot", "--env", "testnet"]
        )
    assert result.exit_code == 0, result.output
    pclient.api_client.post.assert_called_once()
    _, kwargs = pclient.api_client.post.call_args
    assert kwargs["path"] == "account/keys/subkeys"
    assert kwargs["payload"]["public_key"] == SUBKEY
    # default --no-sign → no signature attached
    assert "signature" not in kwargs["payload"]


def test_register_subkey_command_signed(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(
            app,
            ["register-subkey", SUBKEY, "--name", "bot", "--sign", "--env", "testnet"],
        )
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.post.call_args
    assert "signature" in kwargs["payload"]
    assert kwargs["payload"]["signature_timestamp"] > 0


def test_register_subkey_command_evm_l1_key(setup_env_vars):
    pclient = _mock_authed_paradex()
    # EVM path authenticates via _evm_authed_paradex (v2 SIWE), not the stark flow.
    with patch("paradex_cli.main._evm_authed_paradex", return_value=pclient) as mock_evm_auth:
        result = runner.invoke(
            app,
            [
                "register-subkey",
                SUBKEY,
                "--name",
                "evm-bot",
                "--l1-key",
                EVM_KEY,
                "--env",
                "testnet",
            ],
        )
    assert result.exit_code == 0, result.output
    mock_evm_auth.assert_called_once()
    _, kwargs = pclient.api_client.post.call_args
    payload = kwargs["payload"]
    # EVM path: SIWE fields present, stark signature absent.
    assert "siwe_message" in payload and "evm_signature" in payload
    assert "signature" not in payload


def test_list_subkeys_command(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(app, ["list-subkeys", "--with-revoked", "--env", "testnet"])
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.get.call_args
    assert kwargs["path"] == "account/keys/subkeys"
    assert kwargs["params"] == {"with_revoked": "true"}


def test_list_subkeys_command_without_revoked(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(app, ["list-subkeys", "--env", "testnet"])
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.get.call_args
    # default (no --with-revoked) sends no params
    assert kwargs["params"] is None


def test_get_subkey_command(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(app, ["get-subkey", SUBKEY, "--env", "testnet"])
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.get.call_args
    assert kwargs["path"] == f"account/keys/subkeys/{SUBKEY}"


def test_revoke_subkey_command(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(app, ["revoke-subkey", SUBKEY, "--env", "testnet"])
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.delete.call_args
    assert kwargs["path"] == f"account/keys/subkeys/{SUBKEY}"


def test_update_subkey_allowed_cidrs_command(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(
            app,
            [
                "update-subkey-allowed-cidrs",
                SUBKEY,
                "--cidr",
                "203.0.113.0/24",
                "--cidr",
                "198.51.100.42/32",
                "--env",
                "testnet",
            ],
        )
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.put.call_args
    assert kwargs["path"] == f"account/keys/subkeys/{SUBKEY}/allowed-cidrs"
    assert kwargs["payload"] == {
        "allowed_cidrs": ["203.0.113.0/24", "198.51.100.42/32"]
    }


def test_update_subkey_allowed_cidrs_clear(setup_env_vars):
    pclient = _mock_authed_paradex()
    with patch("paradex_cli.main._authed_paradex", return_value=pclient):
        result = runner.invoke(
            app, ["update-subkey-allowed-cidrs", SUBKEY, "--env", "testnet"]
        )
    assert result.exit_code == 0, result.output
    _, kwargs = pclient.api_client.put.call_args
    assert kwargs["payload"] == {"allowed_cidrs": []}
