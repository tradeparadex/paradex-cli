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

Or using Poetry:

```sh
poetry add paradex_cli
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

## Development

To contribute to this project, follow these steps:

### 1. Clone the Repository

```sh
git clone https://github.com/tradeparadex/paradex_cli.git
cd paradex_cli
```

### 2. Install Dependencies

Install the dependencies using Poetry:

```sh
poetry install
```

### 3. Run Tests

Ensure everything is working by running the tests:

```sh
poetry run pytest
```

### 4. Make Your Changes

Make your changes to the codebase.

### 5. Add Tests

Add tests for your new features or bug fixes.

### 6. Run Tests Again

Run the tests again to make sure everything is still working:

```sh
poetry run pytest
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

To build the project, run:

```sh
poetry build
```

## Publishing the Project

To publish the project to PyPI, run:

```sh
poetry publish --build
```

Make sure you have configured your PyPI token:

```sh
poetry config pypi-token.pypi <your-token>
```
