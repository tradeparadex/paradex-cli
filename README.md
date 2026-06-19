# Paradex CLI

[![PyPI version](https://badge.fury.io/py/paradex_cli.svg)](https://badge.fury.io/py/paradex_cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Paradex CLI is a command-line interface (CLI) for managing account contract setups,
including printing account info, adding guardians, changing signers, managing
trade-only subkeys, and more.

### Supported account types

The CLI auto-detects the account contract family and uses the correct interface:

- **Cairo 0** — Argent v0.2.x / v0.3.x (proxy pattern). camelCase entrypoints,
  bare-felt guardian/signer arguments.
- **Cairo 1** — Argent v0.4.0 / v0.5.0, including **EVM (Eip191) accounts** used
  for Ethereum-wallet onboarding. snake_case entrypoints; the `signer` role is
  renamed `owner`, and guardian arguments are `Option<Signer>` enums.

Guardian, escape, and fund-movement (deposit/withdraw/transfer) commands all
work on both families. See the per-command notes below for behaviour that
differs by version.

## Installation

**Run without installing (recommended):**

```sh
uvx paradex-cli <command>
```

**Install as a persistent tool:**

```sh
uv tool install paradex-cli
paradex-cli <command>
```

## Environment Variables

All commands require `PARADEX_ACCOUNT_ADDRESS` and `PARADEX_ACCOUNT_KEY`.

**Option 1 — `.env` file (recommended)**

Copy the example and fill in your credentials. The CLI auto-loads `.env` from the current directory.

```sh
cp .env.example .env
# edit .env with your address and private key
paradex-cli <command>
```

**Option 2 — explicit file path**

Useful when you maintain separate credential files per environment:

```sh
paradex-cli --env-file ~/.paradex/prod.env <command>
```

**Option 3 — inline / shell export**

```sh
PARADEX_ACCOUNT_ADDRESS=0x... PARADEX_ACCOUNT_KEY=0x... paradex-cli <command>
# or
export PARADEX_ACCOUNT_ADDRESS=0x...
export PARADEX_ACCOUNT_KEY=0x...
```

## Commands

### Print Account Info

```sh
paradex-cli print-account-info ACCOUNT_ADDRESS --env ENVIRONMENT
```

### Add Guardian

```sh
paradex-cli add-guardian PUB_KEY --env ENVIRONMENT
```

### Add Guardian Backup

```sh
paradex-cli add-guardian-backup PUB_KEY --env ENVIRONMENT
```

### Change Signer

> **Cairo 0 only.** On Cairo 1 accounts (Argent v0.4.0+) the owner is rotated
> with `change_owner`, which requires a signature from the *new* owner key; use
> the Paradex app/SDK with that key instead.

```sh
paradex-cli change-signer PUB_KEY --env ENVIRONMENT
```

### Sign Invoke Transaction

```sh
paradex-cli sign-invoke-tx FILE_PATH --env ENVIRONMENT
```

### Submit Invoke Transaction

```sh
paradex-cli submit-invoke-tx TX_FILE_PATH SIG_FILES --env ENVIRONMENT
```

### Withdraw to L1

Withdraw balance from Paraclear to bridge on L1.

```sh
paradex-cli withdraw-to-l1 L1_ADDRESS AMOUNT --env ENVIRONMENT
```

### Transfer on L2

Withdraw balance from Paraclear and transfer to a different account on L2.

```sh
paradex-cli transfer-on-l2 L2_ADDRESS AMOUNT --env ENVIRONMENT
```

### Deposit to Paraclear

Deposit balance to Paraclear from L2.

```sh
paradex-cli deposit-to-paraclear AMOUNT --env ENVIRONMENT
```

### Trigger Escape Guardian

On **Cairo 1** accounts the replacement guardian is committed at trigger time and
is required; on **Cairo 0** accounts the argument is ignored (the new guardian is
supplied later to `escape-guardian`).

```sh
# Cairo 1 (Argent v0.4.0+): pass the new guardian public key
paradex-cli trigger-escape-guardian PUB_KEY --env ENVIRONMENT
# Cairo 0: no argument needed
paradex-cli trigger-escape-guardian --env ENVIRONMENT
```

### Escape Guardian

On **Cairo 0** the new guardian public key is passed here; on **Cairo 1** it was
already committed at trigger time, so the `PUB_KEY` argument is ignored.

```sh
paradex-cli escape-guardian PUB_KEY --env ENVIRONMENT
```

### Sign Register Sub-Operator Message

Generates an off-chain SNIP-12 signature that a sub-operator must produce before a vault
operator can call `register_sub_operator` on the Transfer Registry contract.

`PARADEX_ACCOUNT_KEY` must be the **sub-operator's** private key.

```sh
paradex-cli sign-register-sub-operator-message VAULT_ADDRESS SUB_OPERATOR_ADDRESS --env ENVIRONMENT
```

Share the printed `Nonce`, `Expiry`, and `Signature` with the vault operator to complete on-chain registration.

## Subkeys

Subkeys are **trade-only** signing keys registered under a main account: they can
place and cancel orders but cannot deposit, withdraw, transfer, or manage keys.
They are managed entirely via the Paradex API — `PARADEX_ACCOUNT_ADDRESS` /
`PARADEX_ACCOUNT_KEY` must be the **main account** (subkeys can only be created
and revoked by the main account).

### Register a subkey

`PUB_KEY` is the StarkNet public key of the key your bot/strategy will sign with.

```sh
paradex-cli register-subkey PUB_KEY --name "trading-bot" --env ENVIRONMENT
```

**StarkNet main account** — use `--sign` to attach an authorization signature
over `pedersen(account, subkey_pubkey, timestamp, expiry)`. Required when the
backend enforces subkey-registration signatures, harmless otherwise:

```sh
paradex-cli register-subkey PUB_KEY --name "trading-bot" --sign --env ENVIRONMENT
```

**EVM (EIP-191) main account** — authorize with a SIWE `personal_sign` from the
Ethereum key by passing `--l1-key` (or `PARADEX_L1_PRIVATE_KEY`). The SIWE
domain and chain id default per environment; override with `--siwe-domain` /
`--chain-id` if needed:

```sh
PARADEX_L1_PRIVATE_KEY=0x... paradex-cli register-subkey PUB_KEY --name "trading-bot" --env ENVIRONMENT
# or explicitly
paradex-cli register-subkey PUB_KEY --name "trading-bot" --l1-key 0x... --env ENVIRONMENT
```

> **EVM accounts:** all subkey commands (list/get/revoke/update-cidrs), not just
> register, accept `--l1-key` (or `PARADEX_L1_PRIVATE_KEY`). When set, the CLI
> authenticates the EVM account via the SIWE `/v2` flow instead of the StarkNet
> flow. For StarkNet accounts, omit `--l1-key` and set
> `PARADEX_ACCOUNT_ADDRESS`/`PARADEX_ACCOUNT_KEY` as usual.

### List / get subkeys

```sh
paradex-cli list-subkeys --env ENVIRONMENT
paradex-cli list-subkeys --with-revoked --env ENVIRONMENT
paradex-cli get-subkey PUB_KEY --env ENVIRONMENT
# EVM account:
paradex-cli list-subkeys --l1-key 0x... --env ENVIRONMENT
```

### Revoke a subkey

```sh
paradex-cli revoke-subkey PUB_KEY --env ENVIRONMENT
```

### Restrict a subkey to IP ranges

Replaces the subkey's IP allowlist (CIDRs) — useful for pinning a trading bot to
known infrastructure. The provided list fully replaces the previous one; pass no
`--cidr` to clear the allowlist (make the subkey unrestricted).

```sh
paradex-cli update-subkey-allowed-cidrs PUB_KEY --cidr 203.0.113.0/24 --cidr 198.51.100.42/32 --env ENVIRONMENT
# clear:
paradex-cli update-subkey-allowed-cidrs PUB_KEY --env ENVIRONMENT
```

## Development

To contribute to this project, follow these steps:

### 1. Clone the Repository

```sh
git clone https://github.com/tradeparadex/paradex_cli.git
cd paradex_cli
```

### 2. Install Dependencies

```sh
uv sync
```

### 3. Run Tests

```sh
uv run pytest
```

### 4. Make Your Changes

Make your changes to the codebase.

### 5. Add Tests

Add tests for your new features or bug fixes.

### 6. Run Tests Again

```sh
uv run pytest
```

### 7. Commit Your Changes

Commit your changes and push them to your fork:

```sh
git add .
git commit -m "Description of your changes"
git push origin your-branch
```

### 8. Create a Pull Request

Create a pull request against the `main` branch of this repository.

## Building the Project

```sh
uv build
```

## Publishing the Project

```sh
UV_PUBLISH_TOKEN=<your-pypi-token> uv publish
```
