"""Version-aware Argent account operations.

Paradex accounts come in two contract families with incompatible interfaces:

* **Cairo 0** (Argent v0.2.x / v0.3.x, proxy pattern): camelCase entrypoints,
  guardian/signer arguments are bare ``felt`` public keys
  (``changeGuardian(felt)``, ``getSigner() -> felt``).

* **Cairo 1** (Argent v0.4.0 / v0.5.0, incl. EVM/Eip191 accounts): snake_case
  entrypoints, the ``signer`` role was renamed to ``owner``, and guardian
  arguments are ``Option<Signer>`` enums rather than bare felts
  (``change_guardian(Option<Signer>)``, ``get_owner() -> felt``).

This module detects the family at runtime and builds the correct ``Call`` for
each operation. Cairo 1 calldata is constructed explicitly (rather than relying
on a bundled ABI) because the ABI shipped with the deployed proxy is the legacy
Cairo 0 one, and the EVM account class is not bundled at all.

``Signer`` / ``Option<Signer>`` serialization mirrors Argent's Cairo enum layout
(see argent-contracts-starknet ``src/signer/signer_signature.cairo``)::

    enum Signer { Starknet: 0, Secp256k1: 1, Secp256r1: 2, Eip191: 3, Webauthn: 4 }
    Signer::Starknet(pubkey)        -> [0, pubkey]
    Option::Some(x)                 -> [0, <x...>]
    Option::None                    -> [1]

A guardian is always added as a Starknet signer (a stark-curve key), so:

    Some(Signer::Starknet(pubkey))  -> [0, 0, pubkey]
    None                            -> [1]
"""

from enum import Enum

from starknet_py.contract import Contract
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.client_models import Call

# Cairo Signer enum variant indices (argent signer_signature.cairo).
SIGNER_VARIANT_STARKNET = 0

# Cairo Option<T> variant indices.
OPTION_SOME = 0
OPTION_NONE = 1


class AccountKind(Enum):
    """Argent account contract family.

    The guardian/owner management API differs across these families. The split
    that matters is single-owner (v0.4.0) vs multiowner (v0.5.0); the owner's
    *signer type* (Starknet, Secp256k1, Eip191/EVM, Webauthn) is orthogonal —
    both v0.4.0 and v0.5.0 support all signer types and guardians.

    * ``CAIRO0`` — Argent v0.2.x/v0.3.x (proxy): camelCase, bare-felt args
      (``changeGuardian(felt)``, ``getSigner()``).
    * ``CAIRO1`` — Argent v0.4.0 single-owner: snake_case,
      ``change_guardian(Option<Signer>)`` (+ ``change_guardian_backup``),
      ``change_owner(SignerSignature)``, ``get_owner()``.
    * ``CAIRO1_MULTIOWNER`` — Argent v0.5.0 multiowner:
      ``change_guardians(Array<GUID>, Array<Signer>)`` /
      ``change_owners(...)``; ``get_owner()``/``get_guardian()`` still exist.
    """

    CAIRO0 = "cairo0"
    CAIRO1 = "cairo1"
    CAIRO1_MULTIOWNER = "cairo1_multiowner"


def _has(contract: Contract, name: str) -> bool:
    return name in contract.functions


async def _read_version(contract: Contract) -> tuple[int, int, int] | None:
    """Read Argent ``get_version() -> Version{major,minor,patch}`` if present."""
    if not _has(contract, "get_version"):
        return None
    try:
        res = await contract.functions["get_version"].call()
    except Exception:
        return None
    # Cairo 1 returns a Version struct (major, minor, patch); be tolerant of
    # tuple/namedtuple/struct shapes.
    if hasattr(res, "major"):
        return (res.major, res.minor, res.patch)
    if isinstance(res, (list, tuple)) and len(res) >= 3:
        return (res[0], res[1], res[2])
    return None


async def detect_account_kind(contract: Contract) -> AccountKind:
    """Detect the Argent account contract family.

    Primary signal is the on-chain Argent ``get_version()``: ``0.5.x`` is the
    multiowner account, ``0.4.x`` the single-owner Cairo 1 account. We fall back
    to ``contract.data.cairo_version`` and finally ABI probing (for mocks /
    accounts that don't expose ``get_version``).
    """
    version = await _read_version(contract)
    if version is not None:
        major, minor, _ = version
        if (major, minor) >= (0, 5):
            return AccountKind.CAIRO1_MULTIOWNER
        if (major, minor) >= (0, 4):
            return AccountKind.CAIRO1
        return AccountKind.CAIRO0

    data = getattr(contract, "data", None)
    cairo_version = getattr(data, "cairo_version", None)
    if cairo_version == 1:
        # Can't tell single- vs multi-owner without the version; prefer the
        # multiowner API when the multiowner-only entrypoint is present.
        if _has(contract, "change_guardians"):
            return AccountKind.CAIRO1_MULTIOWNER
        return AccountKind.CAIRO1
    if cairo_version == 0:
        return AccountKind.CAIRO0

    if _has(contract, "change_guardians"):
        return AccountKind.CAIRO1_MULTIOWNER
    if _has(contract, "get_owner") or _has(contract, "change_guardian"):
        return AccountKind.CAIRO1
    return AccountKind.CAIRO0


def _is_cairo1(kind: AccountKind) -> bool:
    return kind in (AccountKind.CAIRO1, AccountKind.CAIRO1_MULTIOWNER)


def signer_starknet(pub_key: int) -> list[int]:
    """Serialize ``Signer::Starknet(pub_key)`` (no Option wrapper)."""
    return [SIGNER_VARIANT_STARKNET, pub_key]


def array_of_signers(pub_keys: list[int]) -> list[int]:
    """Serialize ``Array<Signer>`` of Starknet signers: [len, (variant, pk)...]."""
    out = [len(pub_keys)]
    for pk in pub_keys:
        out.extend(signer_starknet(pk))
    return out


def option_some_starknet_signer(pub_key: int) -> list[int]:
    """Serialize ``Some(Signer::Starknet(pub_key))`` for a Cairo 1 call."""
    return [OPTION_SOME, SIGNER_VARIANT_STARKNET, pub_key]


def option_none() -> list[int]:
    """Serialize ``Option::None`` for a Cairo 1 call."""
    return [OPTION_NONE]


def _guardian_option_calldata(pub_key: int) -> list[int]:
    """Encode a guardian argument: ``None`` when pub_key is 0, else ``Some``."""
    if pub_key == 0:
        return option_none()
    return option_some_starknet_signer(pub_key)


def build_change_guardian_call(
    kind: AccountKind,
    account_address: int,
    pub_key: int,
    *,
    remove_guardian_guids: list[int] | None = None,
) -> Call:
    """Build the call to set/replace the guardian.

    - ``CAIRO1_MULTIOWNER`` (v0.5.0): ``change_guardians(guids_to_remove,
      guardians_to_add)``. Pass ``pub_key=0`` with ``remove_guardian_guids`` to
      remove existing guardians (and add none).
    - ``CAIRO1`` (v0.4.0): ``change_guardian(Option<Signer>)`` — ``pub_key=0``
      removes (``Option::None``).
    - ``CAIRO0``: ``changeGuardian(felt)``.
    """
    if kind is AccountKind.CAIRO1_MULTIOWNER:
        to_remove = remove_guardian_guids or []
        add = [pub_key] if pub_key != 0 else []
        calldata = [len(to_remove), *to_remove, *array_of_signers(add)]
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("change_guardians"),
            calldata=calldata,
        )
    if kind is AccountKind.CAIRO1:
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("change_guardian"),
            calldata=_guardian_option_calldata(pub_key),
        )
    return Call(
        to_addr=account_address,
        selector=get_selector_from_name("changeGuardian"),
        calldata=[pub_key],
    )


def build_change_guardian_backup_call(
    kind: AccountKind, account_address: int, pub_key: int
) -> Call:
    """Build the ``change_guardian_backup`` / ``changeGuardianBackup`` call.

    The v0.5.0 multiowner account has no separate "guardian backup" concept
    (multiple guardians are managed via ``change_guardians``), so this is only
    valid for CAIRO0 / CAIRO1 single-owner accounts.
    """
    if kind is AccountKind.CAIRO1_MULTIOWNER:
        raise ValueError(
            "guardian-backup is not supported on Argent v0.5.0 multiowner "
            "accounts; add additional guardians via change_guardians instead"
        )
    if kind is AccountKind.CAIRO1:
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("change_guardian_backup"),
            calldata=_guardian_option_calldata(pub_key),
        )
    return Call(
        to_addr=account_address,
        selector=get_selector_from_name("changeGuardianBackup"),
        calldata=[pub_key],
    )


def build_escape_guardian_call(
    kind: AccountKind, account_address: int, pub_key: int
) -> Call:
    """Build the ``escape_guardian`` / ``escapeGuardian`` call.

    Cairo 1 ``escape_guardian()`` takes NO argument — the new guardian was
    committed at ``trigger_escape_guardian`` time. Cairo 0 ``escapeGuardian``
    takes the new guardian felt.
    """
    if _is_cairo1(kind):
        # Both v0.4.0 and v0.5.0 expose escape_guardian() with no argument;
        # the replacement guardian was committed at trigger time.
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("escape_guardian"),
            calldata=[],
        )
    return Call(
        to_addr=account_address,
        selector=get_selector_from_name("escapeGuardian"),
        calldata=[pub_key],
    )


def build_trigger_escape_guardian_call(
    kind: AccountKind, account_address: int, pub_key: int = 0
) -> Call:
    """Build the ``trigger_escape_guardian`` / ``triggerEscapeGuardian`` call.

    Cairo 1 (both v0.4.0 and v0.5.0) ``trigger_escape_guardian(Option<Signer>)``
    commits the replacement guardian up front. Cairo 0 ``triggerEscapeGuardian()``
    takes no argument.
    """
    if _is_cairo1(kind):
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("trigger_escape_guardian"),
            calldata=_guardian_option_calldata(pub_key),
        )
    return Call(
        to_addr=account_address,
        selector=get_selector_from_name("triggerEscapeGuardian"),
        calldata=[],
    )


async def read_signers(contract: Contract, kind: AccountKind) -> dict[str, int]:
    """Read owner/guardian/guardian_backup public keys, version-aware.

    Returns a dict with keys ``owner``, ``guardian``, ``guardian_backup`` —
    all ints (0 when unset). ``owner`` is the Cairo 0 "signer". The v0.5.0
    multiowner account has no guardian_backup (reported as 0).
    """
    if kind is AccountKind.CAIRO1_MULTIOWNER:
        owner = (await contract.functions["get_owner"].call())[0]
        guardian = (await contract.functions["get_guardian"].call())[0]
        guardian_backup = 0  # no backup-guardian concept on multiowner
    elif kind is AccountKind.CAIRO1:
        owner = (await contract.functions["get_owner"].call())[0]
        guardian = (await contract.functions["get_guardian"].call())[0]
        guardian_backup = (await contract.functions["get_guardian_backup"].call())[0]
    else:
        owner = (await contract.functions["getSigner"].call()).signer
        guardian = (await contract.functions["getGuardian"].call()).guardian
        guardian_backup = (
            await contract.functions["getGuardianBackup"].call()
        ).guardianBackup
    return {"owner": owner, "guardian": guardian, "guardian_backup": guardian_backup}


async def read_guardian_guids(contract: Contract) -> list[int]:
    """Read the current guardian GUIDs (v0.5.0 multiowner), for removal.

    Returns an empty list when there are no guardians or the entrypoint is
    unavailable.
    """
    if not _has(contract, "get_guardians_guids"):
        return []
    res = await contract.functions["get_guardians_guids"].call()
    guids = res[0] if isinstance(res, (list, tuple)) else res
    return list(guids) if guids else []
