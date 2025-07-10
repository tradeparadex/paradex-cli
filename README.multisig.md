# Multisig Usage with Paradex CLI

## Overview

Paradex CLI supports multisig account management and transaction flows on Starknet. The multisig commands allow you to manage signers, thresholds, and submit transactions that require multiple approvals.

## Prerequisites

- Python environment with `poetry` installed
- Paradex CLI installed (`poetry install`)
- Starknet account(s) set up for multisig

## Multisig Commands

To see all available multisig commands:

```bash
poetry run paradex-cli multisig --help
```

### Supported Environments

- `testnet`
- `prod`

Specify the environment with `--env testnet` or `--env prod` (default is `testnet`).

---

## Multisig Workflow

### 1. Change Threshold

Change the number of required signers for a multisig account:

```bash
poetry run paradex-cli multisig change-threshold <MULTISIG_ADDRESS> <NEW_THRESHOLD> --env prod
```

### 2. Add Signers

Add new signers to a multisig account:

```bash
poetry run paradex-cli multisig add-signers <MULTISIG_ADDRESS> <NEW_THRESHOLD> <SIGNER1,SIGNER2,...> --env prod
```

### 3. Remove Signers

Remove signers from a multisig account:

```bash
poetry run paradex-cli multisig remove-signers <MULTISIG_ADDRESS> <NEW_THRESHOLD> <SIGNER1,SIGNER2,...> --env prod
```

### 4. Replace a Signer

Replace an existing signer with a new one:

```bash
poetry run paradex-cli multisig replace-signer <MULTISIG_ADDRESS> <OLD_SIGNER> <NEW_SIGNER> --env prod
```

### 5. Get Multisig Info

Display information about a multisig account:

```bash
poetry run paradex-cli multisig get-info <MULTISIG_ADDRESS> --env prod
```

### 6. Check if an Address is a Signer

```bash
poetry run paradex-cli multisig is-signer <MULTISIG_ADDRESS> <SIGNER_ADDRESS> --env prod
```

### 7. Sign a Transaction

Sign a transaction JSON file (produced by another tool or process):

```bash
poetry run paradex-cli multisig sign-transaction <TX_FILE.json> --env prod
```

### 8. Merge Signatures

Merge multiple signature files with a transaction file for submission:

```bash
poetry run paradex-cli multisig merge-signatures <TX_FILE.json> "<SIG1.json>,<SIG2.json>" <OUT_FILE.json> --env prod
```

### 9. Submit a Transaction

Submit a transaction with merged signatures:

```bash
poetry run paradex-cli multisig submit-transaction <OUT_FILE.json> --env prod
```

---

## Example Multisig Flow

1. **Generate a transaction** (using your own tooling or contract call).
1. **Each signer signs** the transaction file:

  ```bash
  poetry run paradex-cli multisig sign-transaction tx.json --env prod > sig1.json
  # ...repeat for each signer
  ```

1. **Merge all signatures**:

   ```bash
   poetry run paradex-cli multisig merge-signatures tx.json "sig1.json,sig2.json" merged_tx.json --env prod
   ```

1. **Submit the transaction**:

   ```bash
   poetry run paradex-cli multisig submit-transaction merged_tx.json --env prod
   ```

---

## Notes

- All commands support `--env testnet` or `--env prod`.
- The CLI expects transaction and signature files in the format compatible with Argent's multisig backend.
- For more details on each command, use `--help` with the specific command.
