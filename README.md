# Paradex CLI

[![PyPI version](https://badge.fury.io/py/paradex_cli.svg)](https://badge.fury.io/py/paradex_cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Paradex CLI is a command-line interface (CLI) for managing account contract setups,
including printing account info, adding guardians, changing signers, and more.

## Installation

You can install the package via pip:

```sh
pip install paradex_cli
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
paradex_cli print-account-info ACCOUNT_ADDRESS --env ENVIRONMENT
```

### Add Guardian

```sh
paradex_cli add-guardian PUB_KEY --env ENVIRONMENT
```

### Add Guardian Backup

```sh
paradex_cli add-guardian-backup PUB_KEY --env ENVIRONMENT
```

### Change Signer

```sh
paradex_cli change-signer PUB_KEY --env ENVIRONMENT
```

### Sign Invoke Transaction

```sh
paradex_cli sign-invoke-tx FILE_PATH --env ENVIRONMENT
```

### Submit Invoke Transaction

```sh
paradex_cli submit-invoke-tx TX_FILE_PATH SIG_FILES --env ENVIRONMENT
```

### Trigger Escape Guardian

```
paradex_cli trigger-escape-guardian --env ENVIRONMENT
```

### Sign Register Sub-Operator Message

Generates an off-chain SNIP-12 signature that a sub-operator must produce before a vault
operator can call `register_sub_operator` on the Transfer Registry contract.

`PARADEX_ACCOUNT_KEY` must be the **sub-operator's** private key.

```sh
paradex-cli sign-register-sub-operator-message VAULT_ADDRESS SUB_OPERATOR_ADDRESS --env ENVIRONMENT
```

Share the printed `Nonce`, `Expiry`, and `Signature` with the vault operator to complete on-chain registration.

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
