"""Subkey management via the Paradex REST API.

Subkeys are trade-scoped signing keys registered under a main account. They can
place and cancel orders but cannot deposit, withdraw, transfer, or manage other
keys. They live entirely at the API layer (``/v1/account/keys/subkeys``) — there
is no on-chain component — so these helpers talk to the authenticated Paradex
API client rather than invoking a contract.

Registration can optionally carry a signature from the main account's StarkNet
key over ``pedersen([account, subkey_pubkey, timestamp, expiry])`` as ``[r, s]``.
The Paradex backend requires this when the ``EnableSubkeyRegistrationSignature``
feature flag is on; it is harmless (ignored) when off. See
``verifyRegisterSubkeySignature`` in web-api ``handlers/account_keys.go``.

Only the StarkNet-key (stark-curve) authorization path is implemented here. EVM
(EIP-191/SIWE) accounts authorize subkey registration with an L1 ``personal_sign``
that requires the Ethereum wallet, which is outside this CLI's scope.
"""

import time
from datetime import datetime, timedelta, timezone

from starknet_py.hash.utils import compute_hash_on_elements, message_signature

SUBKEYS_PATH = "account/keys/subkeys"

# Keep the signed validity window comfortably under the backend's 10-minute cap.
_DEFAULT_VALIDITY_SECONDS = 5 * 60

# SIWE domain + EIP-155 chain id per environment, mirroring the backend's
# ETHEREUM_SIWE_DOMAINS / ETHEREUM_CHAIN_ID config (infra/helm .../environments).
EVM_SIWE_DEFAULTS = {
    "nightly": ("app.nightly.paradex.trade", 11155111),
    "testnet": ("app.testnet.paradex.trade", 11155111),
    "prod": ("app.paradex.trade", 1),
}

# Statement prefix the backend expects (ethereum/siwe.go
# SiweSubkeyRegistrationStatementPrefix). The subkey pubkey is appended lowercased.
SIWE_SUBKEY_STATEMENT_PREFIX = "Paradex Subkey Registration: "


def _to_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16) if value.startswith("0x") else int(value)


def build_registration_signature(
    account_address: str | int,
    subkey_public_key: str | int,
    private_key: int,
    timestamp: int,
    expiry: int,
) -> list[str]:
    """Sign ``pedersen([account, subkey_pubkey, timestamp, expiry])``.

    Returns the signature as ``["0x<r>", "0x<s>"]`` to match the REST payload.
    """
    msg_hash = compute_hash_on_elements(
        [
            _to_int(account_address),
            _to_int(subkey_public_key),
            timestamp,
            expiry,
        ]
    )
    r, s = message_signature(msg_hash, private_key)
    return [hex(r), hex(s)]


def build_register_payload(
    public_key: str,
    name: str,
    *,
    account_address: str | int | None = None,
    private_key: int | None = None,
    sign: bool = False,
    now: int | None = None,
    validity_seconds: int = _DEFAULT_VALIDITY_SECONDS,
) -> dict:
    """Build the ``POST /account/keys/subkeys`` body for an active subkey.

    When ``sign`` is True, attaches a main-key authorization signature plus its
    timestamp/expiry (required by the backend when subkey-registration
    signatures are enforced). ``account_address`` and ``private_key`` must be
    provided in that case.
    """
    payload: dict = {
        "public_key": public_key,
        "name": name,
        "state": "active",
    }
    if sign:
        if account_address is None or private_key is None:
            raise ValueError(
                "account_address and private_key are required to sign the "
                "registration payload"
            )
        ts = int(now if now is not None else time.time())
        expiry = ts + validity_seconds
        payload["signature"] = build_registration_signature(
            account_address, public_key, private_key, ts, expiry
        )
        payload["signature_timestamp"] = ts
        payload["signature_expiry"] = expiry
    return payload


def evm_siwe_defaults(env: str) -> tuple[str, int]:
    """Return ``(siwe_domain, chain_id)`` for ``env``.

    Raises ``ValueError`` for an environment without a known default (e.g.
    ``local``); the caller can require explicit ``--siwe-domain`` / ``--chain-id``.
    """
    try:
        return EVM_SIWE_DEFAULTS[env]
    except KeyError:
        raise ValueError(
            f"no SIWE defaults for env '{env}'; pass --siwe-domain and --chain-id"
        )


def build_siwe_subkey_message(
    domain: str,
    eth_address: str,
    chain_id: int,
    subkey_public_key: str,
    nonce: str,
    issued_at: datetime,
    expiration_time: datetime,
) -> str:
    """Build the canonical ERC-4361 SIWE message authorising a subkey.

    Mirrors the backend's expectations (ethereum/siwe.go): statement
    ``"Paradex Subkey Registration: <lowercased subkey pubkey>"``, uri
    ``https://<domain>``, version ``1``, and an issuedAt/expirationTime window
    the backend caps at 10 minutes.
    """
    statement = SIWE_SUBKEY_STATEMENT_PREFIX + subkey_public_key.lower()
    return _build_siwe_message(
        domain, eth_address, chain_id, statement, nonce, issued_at, expiration_time
    )


def sign_siwe_message(message: str, eth_private_key: str) -> str:
    """Sign a SIWE message with EIP-191 personal_sign; returns 0x-hex (65 bytes)."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    signed = Account.sign_message(encode_defunct(text=message), eth_private_key)
    sig = signed.signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def eth_address_from_private_key(eth_private_key: str) -> str:
    """Return the checksummed Ethereum address for an L1 private key."""
    from eth_account import Account

    return Account.from_key(eth_private_key).address


def _evm_siwe_headers(
    paradex_address: str,
    eth_private_key: str,
    siwe_domain: str,
    chain_id: int,
    statement: str,
    nonce: str,
    with_expiry: bool,
) -> dict:
    """Build the PARADEX-* SIWE auth/onboarding headers for an EVM account."""
    import base64

    eth_address = eth_address_from_private_key(eth_private_key)
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    expiry = issued + timedelta(seconds=30) if with_expiry else None
    message = _build_siwe_message(
        siwe_domain, eth_address, chain_id, statement, nonce, issued, expiry
    )
    signature = sign_siwe_message(message, eth_private_key)
    return {
        "PARADEX-STARKNET-ACCOUNT": paradex_address,
        "PARADEX-EVM-SIGNATURE": signature,
        "PARADEX-SIWE-MESSAGE": base64.b64encode(message.encode()).decode(),
    }


def _build_siwe_message(domain, address, chain_id, statement, nonce, issued_at, expiration_time):
    from siwe import SiweMessage

    kwargs = dict(
        domain=domain,
        address=address,
        statement=statement,
        uri=f"https://{domain}",
        version="1",
        chain_id=chain_id,
        nonce=nonce,
        issued_at=issued_at.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
    )
    if expiration_time is not None:
        kwargs["expiration_time"] = (
            expiration_time.astimezone(timezone.utc).replace(microsecond=0).isoformat()
        )
    return SiweMessage(**kwargs).prepare_message()


def evm_uncompressed_pubkey(eth_private_key: str) -> str:
    """Return the uncompressed secp256k1 public key (0x04 + 128 hex)."""
    from eth_keys import keys

    priv = keys.PrivateKey(bytes.fromhex(eth_private_key[2:] if eth_private_key.startswith("0x") else eth_private_key))
    return "0x04" + priv.public_key.to_bytes().hex()


def evm_onboard_and_auth(
    http_post,
    http_get,
    eth_private_key: str,
    siwe_domain: str,
    chain_id: int,
) -> tuple[str, str]:
    """Onboard (idempotently) and authenticate an EVM (EIP-191) account.

    Uses the v2 SIWE endpoints (the SDK only speaks the v1 stark flow):
      GET  /onboarding?eth_address=..&account_signer_type=eip191  -> address
      POST /v2/onboarding   (SIWE "Paradex Onboarding")
      POST /v2/auth         (SIWE "Paradex Auth", 30s expiry)     -> jwt

    ``http_get(path, params)`` and ``http_post(path, headers, json)`` are thin
    callables the caller supplies (wrapping the SDK http client / httpx) so this
    stays transport-agnostic and testable. Returns ``(paradex_address, jwt)``.
    """
    import secrets as _secrets

    eth_address = eth_address_from_private_key(eth_private_key)
    uncompressed_pub = evm_uncompressed_pubkey(eth_private_key)

    onb = http_get(
        "onboarding",
        {"eth_address": eth_address, "account_signer_type": "eip191"},
    )
    paradex_address = onb["address"]

    if not onb.get("exists"):
        http_post(
            "v2/onboarding",
            _evm_siwe_headers(
                paradex_address, eth_private_key, siwe_domain, chain_id,
                "Paradex Onboarding", _secrets.token_hex(16), with_expiry=False,
            ),
            {"public_key": uncompressed_pub},
        )

    auth_resp = http_post(
        "v2/auth",
        _evm_siwe_headers(
            paradex_address, eth_private_key, siwe_domain, chain_id,
            "Paradex Auth", _secrets.token_hex(16), with_expiry=True,
        ),
        {},
    )
    return paradex_address, auth_resp["jwt_token"]


def build_evm_register_payload(
    public_key: str,
    name: str,
    *,
    eth_private_key: str,
    siwe_domain: str,
    chain_id: int,
    nonce: str,
    now: datetime | None = None,
    validity_seconds: int = _DEFAULT_VALIDITY_SECONDS,
) -> dict:
    """Build the register-subkey body for an EVM (EIP-191) main account.

    Produces a SIWE ``personal_sign`` authorization (``siwe_message`` +
    ``evm_signature``) instead of the stark-curve ``signature`` — this is what
    the backend requires for EIP-191 accounts (verifyRegisterSubkeySignatureEvm).
    """
    eth_address = eth_address_from_private_key(eth_private_key)
    issued = now or datetime.now(timezone.utc)
    expiry = issued + timedelta(seconds=validity_seconds)
    siwe_message = build_siwe_subkey_message(
        siwe_domain, eth_address, chain_id, public_key, nonce, issued, expiry
    )
    evm_signature = sign_siwe_message(siwe_message, eth_private_key)
    return {
        "public_key": public_key,
        "name": name,
        "state": "active",
        "siwe_message": siwe_message,
        "evm_signature": evm_signature,
    }
