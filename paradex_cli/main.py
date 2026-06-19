import asyncio
import dataclasses
import json
import os
import re
import sys
import time
from decimal import Decimal
from typing import Callable, Optional, Union

import marshmallow_dataclass
import secrets
import typer
from paradex_py.account.starknet import Account as StarknetAccount
from paradex_py.paradex import Paradex, ParadexAccount
from paradex_py.paradex_evm import ParadexEvm
from starknet_py.contract import Contract
from starknet_py.net.signer.stark_curve_signer import KeyPair
from starknet_py.proxy.contract_abi_resolver import ProxyConfig, ProxyResolutionError
from starknet_py.proxy.proxy_check import ArgentProxyCheck, OpenZeppelinProxyCheck, ProxyCheck
from starknet_py.net.models import Address, AddressRepresentation, InvokeV3
from starknet_py.net.client import Client
from starknet_py.constants import RPC_CONTRACT_ERROR
from starknet_py.net.client_errors import ClientError
from starknet_py.net.client_models import Call
from starknet_py.hash.selector import get_selector_from_name
from dotenv import load_dotenv

from paradex_cli.account_ops import (
    AccountKind,
    build_change_guardian_backup_call,
    build_change_guardian_call,
    build_escape_guardian_call,
    build_trigger_escape_guardian_call,
    detect_account_kind,
    read_guardian_guids,
    read_signers,
)
from paradex_cli.subkeys import (
    SUBKEYS_PATH,
    build_evm_register_payload,
    build_register_payload,
    eth_address_from_private_key,
    evm_onboard_and_auth,
    evm_siwe_defaults,
)


class _CleanErrorGroup(typer.core.TyperGroup):
    """Surface expected runtime failures as a concise message instead of a
    Python traceback. On-chain reverts (``ClientError``) and client-side
    validation (``ValueError``) are user-facing errors, not bugs — print them
    cleanly and exit non-zero."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except ClientError as err:
            typer.secho(f"Error: {err.message}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        except ValueError as err:
            typer.secho(f"Error: {err}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)


app = typer.Typer(
    cls=_CleanErrorGroup,
    help="""Manage account contract setup.

    Supports both Cairo 0 (Argent v0.2.x/v0.3.x proxy) and Cairo 1
    (Argent v0.4.0/v0.5.0, incl. EVM/Eip191) accounts; the correct ABI is
    selected automatically per account.

    Account & guardian:
    - Print account info
    - Add guardian / Add guardian backup
    - Change signer (Cairo 0 only)
    - Trigger / escape guardian
    - Sign invoke tx / Submit invoke tx

    Funds:
    - Deposit to Paraclear / Withdraw to L1 / Transfer on L2

    Subkeys (trade-only keys):
    - register-subkey / list-subkeys / get-subkey / revoke-subkey
    - update-subkey-allowed-cidrs
    """,
    # rich_markup_mode="rich",
)
option_env = typer.Option("testnet", help="local, nightly, staging, testnet, prod")
# Shared option for on-chain commands: pass an EVM (EIP-191) account's Ethereum
# private key to sign on-chain as that account; omit for a StarkNet (L2-key) account.
option_l1_key = typer.Option(
    None,
    "--l1-key",
    envvar="PARADEX_L1_PRIVATE_KEY",
    help="EVM (EIP-191) account: Ethereum private key to sign on-chain. "
    "Omit for a StarkNet account (uses PARADEX_ACCOUNT_KEY).",
)


@app.callback()
def check_env_vars(
    env_file: Optional[str] = typer.Option(None, "--env-file", help="Path to a .env file with credentials"),
):
    """
    Check if required environment variables are set.
    """
    if env_file:
        load_dotenv(env_file, override=True)

    # Refresh the module-level credentials from the environment on every
    # invocation. They are captured at import for convenience, but the env may
    # be populated after import (an --env-file, or a process that sets the vars
    # later), so re-read them here — this callback runs before every command.
    global ACCOUNT_ADDRESS, ACCOUNT_KEY
    ACCOUNT_ADDRESS = os.environ.get("PARADEX_ACCOUNT_ADDRESS")
    ACCOUNT_KEY = os.environ.get("PARADEX_ACCOUNT_KEY")

    required_vars = ["PARADEX_ACCOUNT_ADDRESS", "PARADEX_ACCOUNT_KEY"]
    missing_vars = [var for var in required_vars if var not in os.environ]

    if missing_vars:
        typer.echo(f"Missing required environment variables: {', '.join(missing_vars)}", err=True)
        raise typer.Exit(code=1)


# Accounts for Private StarkNet
load_dotenv()  # no-op if no .env present; populates os.environ before reading below
ACCOUNT_ADDRESS = os.environ.get("PARADEX_ACCOUNT_ADDRESS")
ACCOUNT_KEY = os.environ.get("PARADEX_ACCOUNT_KEY")

# Transfer Registry contract addresses per environment
TRANSFER_REGISTRY_ADDRESSES = {
    "nightly": "0x4022ac4eb15dcacd45e441c5b070a12d0c4163ab26d45da8e9e01b3451aabe2",
    "staging": "0x5be80d1cceb9379a0d04141aa537cb936c41fddd0b7a3136d697227614a2658",
    "testnet": "0x057311bfe61fb0ba49dd49410eee51c1a605fe07ec5e4e6e64472f4fde84b43e",
    "prod": "0x0355b9f48262d37607098294a37aea883cf34cb81458039e8c0d0871a4f4e4e8",
}


def int_16(val):
    return int(val, 16)


class StarkwareETHProxyCheck(ProxyCheck):
    async def implementation_address(self, address: Address, client: Client) -> Optional[int]:
        return await self.get_implementation(
            address=address,
            client=client,
            get_class_func=client.get_class_hash_at,
            regex_err_msg=r"(is not deployed)",
        )

    async def implementation_hash(self, address: Address, client: Client) -> Optional[int]:
        return await self.get_implementation(
            address=address,
            client=client,
            get_class_func=client.get_class_by_hash,
            regex_err_msg=r"(is not declared)",
        )

    @staticmethod
    async def get_implementation(
        address: Address, client: Client, get_class_func: Callable, regex_err_msg: str
    ) -> Optional[int]:
        call = StarkwareETHProxyCheck._get_implementation_call(address=address)
        err_msg = r"(Entry point 0x[0-9a-f]+ not found in contract)|" + regex_err_msg
        try:
            (implementation,) = await client.call_contract(call=call)
            await get_class_func(implementation)
        except ClientError as err:
            if re.search(err_msg, err.message, re.IGNORECASE) or err.code == RPC_CONTRACT_ERROR:
                return None
            raise err
        return implementation

    @staticmethod
    def _get_implementation_call(address: Address) -> Call:
        return Call(
            to_addr=address,
            selector=get_selector_from_name("implementation"),
            calldata=[],
        )


def get_proxy_config():
    return ProxyConfig(
        max_steps=5,
        proxy_checks=[StarkwareETHProxyCheck(), ArgentProxyCheck(), OpenZeppelinProxyCheck()],
    )

async def load_contract_from_account(
    address: AddressRepresentation,
    account: ParadexAccount,
    proxy_config: Union[bool, ProxyConfig] = get_proxy_config(),
) -> Contract:
    try:
        return await Contract.from_address(
            address=address, provider=account.starknet, proxy_config=proxy_config
        )
    except ProxyResolutionError:
        # Cairo 1 accounts (Argent v0.4.0/v0.5.0, incl. EVM/Eip191) are declared
        # directly, not behind a proxy, so proxy resolution fails. Fall back to
        # loading the on-chain ABI directly. Callers passing proxy_config=False
        # never reach here.
        return await Contract.from_address(
            address=address, provider=account.starknet, proxy_config=False
        )
    except ClientError as err:
        # Some RPC endpoints don't expose the methods the proxy-checks rely on
        # (e.g. get_storage_at -> "method not allowed"). Cairo 1 accounts are
        # not proxies, so retry with proxy resolution disabled.
        if proxy_config is not False and "method not allowed" in (err.message or "").lower():
            return await Contract.from_address(
                address=address, provider=account.starknet, proxy_config=False
            )
        raise


def print_invoke(invoke: InvokeV3, file=sys.stdout):
    invoke_schema = marshmallow_dataclass.class_schema(InvokeV3)()
    print(invoke_schema.dumps(invoke), file=file)


def load_invoke(file) -> InvokeV3:
    invoke_schema = marshmallow_dataclass.class_schema(InvokeV3)()
    invoke: InvokeV3 = invoke_schema.loads(file.read().strip())
    # Needed because `calldata` marshmallow_field is fields.String()
    if hasattr(invoke, 'calldata'):
        calldata = list(map(lambda v: int(v), invoke.calldata))
        invoke = dataclasses.replace(invoke, calldata=calldata)
    return invoke


def load_signature(file) -> list[int]:
    return json.loads(file.read().strip())


async def _change_signer(saccount: StarknetAccount, contract: Contract, pub_key: str):
    # NOTE: the historical Cairo 0 implementation invoked `changeGuardian` here;
    # that is preserved for Cairo 0 accounts. Cairo 1 (v0.4.0+) renamed the role
    # to "owner" and `change_owner` requires a signature from the *new* owner
    # over a ChangeOwnerSignature message, which the CLI cannot produce without
    # the new owner's private key. We surface that limitation explicitly rather
    # than emit a call the contract will reject.
    kind = await detect_account_kind(contract)
    if kind is AccountKind.CAIRO1:
        raise typer.BadParameter(
            "change-signer is not supported on Cairo 1 accounts (Argent v0.4.0+). "
            "change_owner requires a signature from the new owner key; use the "
            "owner key directly via the Paradex app/SDK to rotate the owner."
        )

    need_multisig = await _check_multisig_required(contract)
    print("Change signer...")
    funcName = 'changeGuardian'
    call = contract.functions[funcName].prepare_invoke_v3(
        newGuardian=int_16(pub_key),
    )
    prepared_invoke = await saccount.prepare_invoke(calls=call, auto_estimate=True)
    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _change_guardian(saccount: StarknetAccount, contract: Contract, guardian_pub_key: str):
    kind = await detect_account_kind(contract)
    need_multisig = await _check_multisig_required(contract)

    print("Change guardian...")
    funcName = 'changeGuardian'
    pub_key = int_16(guardian_pub_key)
    remove_guids = None
    if kind is AccountKind.CAIRO1_MULTIOWNER and pub_key == 0:
        # Removing the guardian(s) on a multiowner account requires their GUIDs.
        remove_guids = await read_guardian_guids(contract)
    call = build_change_guardian_call(
        kind, contract.address, pub_key, remove_guardian_guids=remove_guids
    )
    prepared_invoke = await saccount.prepare_invoke(calls=call, auto_estimate=True)
    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _change_guardian_backup(saccount: StarknetAccount, contract: Contract, pub_key: str):
    kind = await detect_account_kind(contract)
    need_multisig = await _check_multisig_required(contract)

    print("Change guardian backup...")
    funcName = 'changeGuardianBackup'
    call = build_change_guardian_backup_call(kind, contract.address, int_16(pub_key))
    prepared_invoke = await saccount.prepare_invoke(calls=call, auto_estimate=True)

    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _check_multisig_required(contract: Contract):
    kind = await detect_account_kind(contract)
    signers = await read_signers(contract, kind)
    print("Current owner:", hex(signers["owner"]))
    print("Current guardian:", hex(signers["guardian"]))
    print("Current guardian backup:", hex(signers["guardian_backup"]))

    need_multisig = signers["guardian_backup"] != 0 or signers["guardian"] != 0
    return need_multisig


async def _wait_for_tx(saccount: StarknetAccount, tx_hash: int, attempts: int = 20) -> None:
    """Poll for terminal tx status, tolerating transient 'Internal error'
    (-32603) responses that the RPC endpoint may return on a status query
    shortly after submission."""
    for _ in range(attempts):
        try:
            status = await saccount.client.get_transaction_status(tx_hash)
        except ClientError as err:
            if "internal error" in (err.message or "").lower():
                await asyncio.sleep(3)
                continue
            raise
        exec_status = str(getattr(status, "execution_status", ""))
        if exec_status.endswith("SUCCEEDED"):
            print("Transaction SUCCEEDED:", hex(tx_hash))
            return
        if exec_status.endswith("REVERTED"):
            raise RuntimeError(
                f"Transaction reverted: {hex(tx_hash)} — {getattr(status, 'failure_reason', '')}"
            )
        await asyncio.sleep(3)
    print(f"Transaction submitted (status pending): {hex(tx_hash)}")


async def _process_invoke(
    saccount: StarknetAccount,
    contract: Contract,
    need_multisig,
    prepared_invoke: InvokeV3,
    multisig_filename: str,
):
    if not need_multisig:
        # Signer signs invoke payload
        owner_signature = saccount.signer.sign_transaction(prepared_invoke)
        # Invoke contract function with signatures
        invoke_result = await saccount.invoke(contract, prepared_invoke, owner_signature)
        print("Waiting tx hash:", hex(invoke_result.hash))
        await _wait_for_tx(saccount, invoke_result.hash)
    else:
        # Serialize dict to a JSON file
        multisig_filename = f'{multisig_filename}.json'
        with open(multisig_filename, 'w') as f:
            print_invoke(prepared_invoke, file=f)
        print("Action requires multiple signatures")
        print(f"Prepared invoke saved to {multisig_filename}")
        print(
            "Please sign tx with sign-invoke-tx command and submit with submit-invoke-tx command"
        )


async def _print_account_info(contract: Contract):
    kind = await detect_account_kind(contract)
    print("Account type:", kind.value)

    signers = await read_signers(contract, kind)
    owner_label = "owner" if kind is AccountKind.CAIRO1 else "signer"
    print(f"Current {owner_label} pubkey:", hex(signers["owner"]))
    print("Current guardian pubkey:", hex(signers["guardian"]))
    print("Current guardian backup pubkey:", hex(signers["guardian_backup"]))


async def _fetch_signers_pubkeys(contract: Contract) -> list[int]:
    kind = await detect_account_kind(contract)
    signers = await read_signers(contract, kind)
    return [
        hex(signers["owner"]),
        hex(signers["guardian"]),
        hex(signers["guardian_backup"]),
    ]


async def _sign_invoke_tx(paccount: ParadexAccount, file_path: str):
    with open(file_path) as f:
        invoke = load_invoke(f)
    print_invoke(invoke)
    signature = paccount.starknet.signer.sign_transaction(invoke)
    pub_key_short = hex(paccount.starknet.signer.public_key)[: 2 + 7]  # 0x + 7 chars
    basename = os.path.basename(file_path)
    opname, _ = os.path.splitext(basename)
    filename = f'{opname}_{pub_key_short}.sig'
    with open(filename, 'w') as f:
        f.write(json.dumps({hex(paccount.starknet.signer.public_key): signature}))
    print(f"Signature saved to {filename}")


async def _submit_invoke_tx(paccount: ParadexAccount, tx_file, sig_files):
    with open(tx_file) as f:
        invoke = load_invoke(f)
    signatures = dict()
    for sig_file in sig_files:
        with open(sig_file) as f:
            sig = load_signature(f)
            signatures.update(sig)
    sorted_sig = list[int]()
    contract = await load_contract_from_account(paccount.l2_address, paccount)
    pubkeys = await _fetch_signers_pubkeys(contract)
    for pubkey in pubkeys:
        if pubkey in signatures:
            sorted_sig.append(signatures[pubkey])
    sorted_sig = sum(sorted_sig, [])
    print("Contract address:", hex(contract.address))
    invoke_result = await paccount.starknet.invoke(contract, invoke, sorted_sig)
    print("Waiting tx hash:", hex(invoke_result.hash))
    await invoke_result.wait_for_acceptance()


@app.command()
def print_account_info(
    acc: str = typer.Argument(..., help="Account address to print summary for"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Print summary information for a given account.

    Args:
        acc (str): Account address to print summary for.
        env (str): Environment to use (optional).

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    contract = asyncio.run(load_contract_from_account(int_16(acc), paccount))
    asyncio.run(_print_account_info(contract))


@app.command()
def add_guardian_backup(
    pub_key: str = typer.Argument(default=None, help="Public key of the guardian backup to add"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Adds a guardian backup to the contract.

    Args:
        pub_key (str, optional): Public key of the guardian backup to add. If not provided, a new guardian backup key will be generated.
        env (str): Environment to use for the operation.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    if pub_key is None:
        guardian_backup_key_file = "guardian_backup.key"
        print("Generating guardian pubkey...")
        if os.path.exists(guardian_backup_key_file):
            private = KeyPair.from_private_key(open(guardian_backup_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + secrets.token_bytes(32).hex())
            with open(guardian_backup_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_guardian_backup(paccount.starknet, contract, pub_key))


@app.command()
def add_guardian(
    pub_key: str = typer.Argument(..., help="Public key of the guardian to add"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Adds a guardian to the contract.

    Args:
        pub_key (str): Public key of the guardian to add.
        env (str): Environment to use for the operation.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    if pub_key is None:
        print("Generating guardian pubkey...")
        guardian_key_file = "guardian.key"
        if os.path.exists(guardian_key_file):
            private = KeyPair.from_private_key(open(guardian_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + secrets.token_bytes(32).hex())
            with open(guardian_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_guardian(paccount.starknet, contract, pub_key))


@app.command()
def change_signer(
    pub_key: str = typer.Argument(..., help="Public key of the signer to replace"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Change the signer of the contract.

    Args:
        pub_key (str): Public key of the signer to replace.
        env (str): Environment to use (e.g., 'testnet', 'mainnet').

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    if pub_key is None:
        print("Generating signer pubkey...")
        guardian_key_file = "signer.key"
        if os.path.exists(guardian_key_file):
            private = KeyPair.from_private_key(open(guardian_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + secrets.token_bytes(32).hex())
            with open(guardian_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_signer(paccount.starknet, contract, pub_key))


@app.command()
def sign_invoke_tx(
    file_path: str = typer.Argument(..., help="Filepath to invoke tx json"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Sign prepared transaction file with current account

    Args:
        file_path (str): Filepath to the invoke tx JSON file.
        env (str): Environment to use for signing the transaction.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_sign_invoke_tx(paccount, file_path))


@app.command()
def submit_invoke_tx(
    tx_file_path: str = typer.Argument(..., help="File with invoke transaction"),
    sig_files: list[str] = typer.Argument(..., help="Files with signatures"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Submits an invoke transaction with provided signatures

    Args:
        tx_file_path (str): Path to the file with the invoke transaction.
        sig_files (list[str]): List of paths to the files with the signatures.
        env (str): Environment configuration.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_submit_invoke_tx(paccount, tx_file=tx_file_path, sig_files=sig_files))


async def _withdraw_to_l1(paccount: ParadexAccount, l1_recipient: str, amount_decimal: Decimal):
    paraclear_address = paccount.config.paraclear_address
    usdc_address = paccount.config.bridged_tokens[0].l2_token_address

    account_contract = await load_contract_from_account(
        address=paccount.l2_address, account=paccount
    )
    paraclear_contract = await load_contract_from_account(
        address=paraclear_address, account=paccount, proxy_config=False
    )
    print(f"Paraclear Contract: {paraclear_address}")
    paraclear_decimals = paccount.config.paraclear_decimals
    usdc_decimals = paccount.config.bridged_tokens[0].decimals
    l2_bridge_address = paccount.config.bridged_tokens[0].l2_bridge_address

    l2_bridge_contract = await load_contract_from_account(
        address=l2_bridge_address, account=paccount
    )
    l2_bridge_version = await l2_bridge_contract.functions["get_version"].call()
    l2_bridge_version = (
        l2_bridge_version[0] if type(l2_bridge_version) is tuple else l2_bridge_version.version
    )
    print(f"USDC Bridge Contract: {hex(l2_bridge_contract.address)}")

    token_asset_bal = await paraclear_contract.functions["get_token_asset_balance"].call(
        account=paccount.l2_address, token_address=int_16(usdc_address)
    )
    balance = token_asset_bal[0]
    print(f"USDC balance on paraclear: {balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to withdraw from paraclear: {amount_decimal} USDC -> {amount_paraclear}")
    amount_bridge = int(amount_decimal * 10**usdc_decimals)
    print(f"Amount to withdraw from bridge: {amount_decimal} USDC -> {amount_bridge}")

    l1_recipient_arg = int_16(l1_recipient)
    calls = [
        paraclear_contract.functions["withdraw"].prepare_invoke_v3(
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
    ]
    if l2_bridge_version >= 2:
        # StarkGate v2 (Cairo 1) multi-token bridge:
        # initiate_token_withdraw(l1_token: EthAddress, l1_recipient: EthAddress, amount: u256)
        l1_token_address = paccount.config.bridged_tokens[0].l1_token_address
        calls.append(
            l2_bridge_contract.functions["initiate_token_withdraw"].prepare_invoke_v3(
                l1_token={"address": int_16(l1_token_address)},
                l1_recipient={"address": l1_recipient_arg},
                amount=amount_bridge,
            )
        )
    else:
        # Legacy single-token bridge: initiate_withdraw(l1_recipient: felt, amount: felt)
        calls.append(
            l2_bridge_contract.functions["initiate_withdraw"].prepare_invoke_v3(
                l1_recipient=l1_recipient_arg,
                amount=amount_bridge,
            )
        )
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'withdrawToL1'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, auto_estimate=True)

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def withdraw_to_l1(
    l1_address: str = typer.Argument(..., help="L1 address to transfer to"),
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Withdraw balance from Paraclear to bridge on L1

    Args:
        l1_address (str): L1 address to transfer the balance to.
        amount_decimal (str): Amount to transfer.
        env (str): Environment configuration (optional).

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_withdraw_to_l1(paccount, l1_address, Decimal(amount_decimal)))


async def _transfer_on_l2(
    paccount: ParadexAccount, target_l2_address: str, amount_decimal: Decimal
):
    paraclear_address = paccount.config.paraclear_address
    usdc_address = paccount.config.bridged_tokens[0].l2_token_address

    account_contract = await load_contract_from_account(
        address=paccount.l2_address, account=paccount
    )
    paraclear_contract = await load_contract_from_account(
        address=paraclear_address, account=paccount, proxy_config=False
    )
    print(f"Paraclear Contract: {paraclear_address}")
    paraclear_decimals = paccount.config.paraclear_decimals

    usdc_contract = await load_contract_from_account(
        address=usdc_address, account=paccount
    )
    usdc_decimals = paccount.config.bridged_tokens[0].decimals

    token_asset_bal = await paraclear_contract.functions["get_token_asset_balance"].call(
        account=paccount.starknet.address, token_address=int_16(usdc_address)
    )
    balance = token_asset_bal[0]

    print(f"USDC balance on paraclear: {balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to withdraw from paraclear: {amount_paraclear}")
    amount_bridge = int(amount_decimal * 10**usdc_decimals)
    print(f"Amount to transfer to {target_l2_address}: {amount_bridge}")
    calls = [
        paraclear_contract.functions["withdraw"].prepare_invoke_v3(
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
        usdc_contract.functions["increase_allowance"].prepare_invoke_v3(
            spender=int_16(paraclear_address), added_value=amount_bridge
        ),
        paraclear_contract.functions["deposit_on_behalf_of"].prepare_invoke_v3(
            recipient=int_16(target_l2_address),
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
    ]
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'transferOnL2'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, auto_estimate=True)

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def transfer_on_l2(
    l2_address: str = typer.Argument(..., help="L2 address to transfer to"),
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Withdraw balance from Paraclear and transfer to different account on L2

    Args:
        l2_address (str): The L2 address to transfer the balance to.
        amount_decimal (str): The amount to transfer.
        env (str): The environment to use for the transfer.

    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_transfer_on_l2(paccount, l2_address, Decimal(amount_decimal)))


async def _deposit_to_paraclear(paccount: ParadexAccount, amount_decimal: Decimal):

    paraclear_address = paccount.config.paraclear_address
    usdc_address = paccount.config.bridged_tokens[0].l2_token_address

    account_contract = await load_contract_from_account(
        address=paccount.l2_address, account=paccount
    )
    paraclear_contract = await load_contract_from_account(
        address=paraclear_address, account=paccount, proxy_config=False
    )
    print(f"Paraclear Contract: {paraclear_address}")
    paraclear_decimals = paccount.config.paraclear_decimals

    usdc_contract = await load_contract_from_account(
        address=usdc_address, account=paccount
    )
    usdc_decimals = paccount.config.bridged_tokens[0].decimals
    print(f"usdc_address: {usdc_address}")
    token_asset_bal = await paraclear_contract.functions["get_token_asset_balance"].call(
        account=paccount.l2_address, token_address=int_16(usdc_address)
    )
    balance = token_asset_bal[0]
    print(f"USDC balance on paraclear: {balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to deposit to paraclear: {amount_paraclear}")
    amount_usdc = int(amount_decimal * 10**usdc_decimals)
    increase_allowance_func_name = (
        "increase_allowance"
        if "increase_allowance" in usdc_contract.functions
        else "increaseAllowance"
    )
    calls = [
        usdc_contract.functions[increase_allowance_func_name].prepare_invoke_v3(
            spender=int_16(paraclear_address), added_value=amount_usdc
        ),
        paraclear_contract.functions["deposit"].prepare_invoke_v3(
            int_16(usdc_address), amount_paraclear
        ),
    ]
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'depositToParaclear'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, auto_estimate=True)

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def deposit_to_paraclear(
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Deposit balance to Paraclear from L2

    Args:
        amount_decimal (str): The amount to transfer.
        env (str): The environment to use.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_deposit_to_paraclear(paccount, Decimal(amount_decimal)))



async def _trigger_escape_guardian(paccount: ParadexAccount, new_guardian_pub_key: str = "0x0"):
    contract = await load_contract_from_account(paccount.l2_address, paccount)
    kind = await detect_account_kind(contract)
    print(f"Contract: {paccount.l2_address}")

    # On Cairo 1 the replacement guardian is committed at trigger time and is
    # required; on Cairo 0 trigger takes no argument and the guardian is passed
    # later to escape-guardian.
    if kind is AccountKind.CAIRO1 and int_16(new_guardian_pub_key) == 0:
        raise typer.BadParameter(
            "Cairo 1 accounts require the new guardian public key at "
            "trigger-escape-guardian time. Pass it as the argument."
        )

    print("Trigger escape guardian...")
    funcName = 'triggerEscapeGuardian'
    call = build_trigger_escape_guardian_call(
        kind, contract.address, int_16(new_guardian_pub_key)
    )
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=call, auto_estimate=True)
    await _process_invoke(paccount.starknet, contract, False, prepared_invoke, funcName)



@app.command()
def trigger_escape_guardian(
    pub_key: str = typer.Argument(
        "0x0",
        help="Public key of the replacement guardian (required for Cairo 1 / "
        "Argent v0.4.0+ accounts; ignored for Cairo 0).",
    ),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Triggers the escape guardian for the given account.

    Args:
        pub_key (str): Replacement guardian public key (Cairo 1 only).
        env (str): The environment to trigger the escape guardian in.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    asyncio.run(_trigger_escape_guardian(paccount, pub_key))

async def _escape_guardian(saccount: StarknetAccount, contract: Contract, guardian_pub_key: str):
    kind = await detect_account_kind(contract)
    need_multisig = await _check_multisig_required(contract)

    print("Escape guardian...")
    funcName = 'escapeGuardian'
    # Cairo 1 escape_guardian() takes no argument (guardian was set at trigger
    # time); Cairo 0 escapeGuardian(felt) takes the new guardian here.
    call = build_escape_guardian_call(kind, contract.address, int_16(guardian_pub_key))
    prepared_invoke = await saccount.prepare_invoke(calls=call, auto_estimate=True)
    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


@app.command()
def escape_guardian(
    pub_key: str = typer.Argument(..., help="Public key of the new guardian"),
    l1_key: str = option_l1_key,
    env: str = option_env,
):
    """
    Escape guardian for the given account.

    Args:
        pub_key (str): Public key of the new guardian to set.
        env (str): The environment to trigger the escape guardian in.

    Returns:
        None
    """
    paccount = _onchain_account(env, l1_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_escape_guardian(paccount.starknet, contract, pub_key))


async def _sign_register_sub_operator_message(
    vault_address: str,
    sub_operator_address: str,
    env: str,
    output_json: bool = False,
):
    """
    Build and sign the SNIP-12 typed data message required to register a sub-operator
    to a vault via the Transfer Registry contract.

    The caller must be the sub-operator: set PARADEX_ACCOUNT_KEY to the sub-operator's
    private key and pass its on-chain address as sub_operator_address.

    Prints nonce, expiry, and the [r, s] signature to stdout.  Pass those values to
    the vault operator so they can submit register_sub_operator on-chain.
    """
    if env not in TRANSFER_REGISTRY_ADDRESSES:
        typer.echo(
            f"Unsupported environment '{env}'. "
            f"Choose from: {', '.join(TRANSFER_REGISTRY_ADDRESSES)}",
            err=True,
        )
        raise typer.Exit(code=1)

    # Sub-operator signing is a StarkNet-key off-chain SNIP-12 signature.
    paccount = _onchain_account(env)

    transfer_registry_address = TRANSFER_REGISTRY_ADDRESSES[env]

    # Fetch current nonce for the sub-operator from the registry contract
    result = await paccount.starknet.client.call_contract(
        call=Call(
            to_addr=int(transfer_registry_address, 16),
            selector=get_selector_from_name("nonces"),
            calldata=[int(sub_operator_address, 16)],
        ),
    )
    current_nonce = result[0]

    expiry_ms = int(time.time() * 1000) + 1000 * 60 * 60 * 24  # 24 hours from now
    chain_id = paccount.config.starknet_chain_id  # hex string, e.g. "0x505249564154..."

    message = {
        "types": {
            "StarknetDomain": [
                {"name": "name", "type": "shortstring"},
                {"name": "version", "type": "shortstring"},
                {"name": "chainId", "type": "shortstring"},
                {"name": "revision", "type": "shortstring"},
            ],
            "SubOperatorRegistrationMessage": [
                {"name": "vault", "type": "ContractAddress"},
                {"name": "sub_operator", "type": "ContractAddress"},
                {"name": "nonce", "type": "felt"},
                {"name": "expiry", "type": "timestamp"},
            ],
        },
        "primaryType": "SubOperatorRegistrationMessage",
        "domain": {
            "name": "Paradex",
            "version": "v1",
            "chainId": chain_id,
            "revision": 1,
        },
        "message": {
            "vault": vault_address,
            "sub_operator": sub_operator_address,
            "nonce": current_nonce,
            "expiry": expiry_ms,
        },
    }

    signature = paccount.starknet.sign_message(typed_data=message)
    if output_json:
        print(json.dumps({"nonce": current_nonce, "expiry": expiry_ms, "signature": list(signature)}))
    else:
        print(f"Nonce: {current_nonce}")
        print(f"Expiry: {expiry_ms}")
        print(f"Signature: {list(signature)}")


@app.command()
def sign_register_sub_operator_message(
    vault_address: str = typer.Argument(..., help="Vault contract address"),
    sub_operator_address: str = typer.Argument(..., help="Sub-operator address to register"),
    env: str = option_env,
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Generate a signature for registering a sub-operator to a vault.

    The sub-operator signs an off-chain SNIP-12 message that the vault operator
    later submits on-chain via register_sub_operator.

    PARADEX_ACCOUNT_KEY must be the private key of the sub-operator account
    identified by sub_operator_address.

    Outputs the nonce, expiry timestamp (ms), and [r, s] signature.  Share
    these values with the vault operator to complete the registration.
    """
    asyncio.run(
        _sign_register_sub_operator_message(vault_address, sub_operator_address, env, json_output)
    )


def _authed_paradex(env: str) -> Paradex:
    """Return a Paradex client authenticated as the main account.

    ``Paradex(...)`` only auto-initialises the account (and thus onboards +
    auths) when an ``l1_address`` is supplied, so we initialise explicitly with
    the L2 key. ``init_account`` runs onboarding + auth, leaving a JWT on the
    api_client for the private subkey endpoints. ``l1_address="0x0"`` matches
    how the other commands construct the account from an L2 key.
    """
    pclient = Paradex(env=env)
    pclient.init_account(l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    return pclient


def _evm_authed_paradex(
    env: str, l1_key: str, siwe_domain: str | None, chain_id: int | None
) -> Paradex:
    """Return a Paradex client authenticated as an EVM (EIP-191) account.

    The SDK only implements the v1 stark onboarding/auth flow, so we run the
    v2 SIWE onboarding+auth ourselves and inject the resulting JWT into the
    api_client (set_token sets the Authorization header used by all calls).
    """
    if siwe_domain is None or chain_id is None:
        d, c = evm_siwe_defaults(env)
        siwe_domain = siwe_domain or d
        chain_id = chain_id if chain_id is not None else c

    pclient = Paradex(env=env)
    ac = pclient.api_client
    v1_url = ac.api_url  # https://api.<env>.paradex.trade/v1
    root_url = v1_url.rsplit("/v1", 1)[0]  # v2 endpoints live at the root, not under /v1

    def http_get(path, params):
        return ac.get(api_url=v1_url, path=path, params=params)

    def http_post(path, headers, json_body):
        # v2 onboarding/auth are rooted at the host, not under /v1.
        base = root_url if path.startswith("v2/") else v1_url
        return ac.post(api_url=base, path=path, payload=json_body, headers=headers)

    _, jwt = evm_onboard_and_auth(http_post, http_get, l1_key, siwe_domain, chain_id)
    ac.set_token(jwt)
    return pclient


def _onchain_account(env: str, l1_key: str | None = None):
    """Return an account capable of signing on-chain transactions.

    - StarkNet account (default): a ``ParadexAccount`` built from the L2 key.
    - EVM (EIP-191) account: when ``l1_key`` is supplied, a ``ParadexEvm``
      account whose ``.starknet`` is backed by the EIP-191 signer (requires
      paradex_py with EIP-191 on-chain signing). Both expose ``.starknet``,
      ``.config`` and ``.l2_address``, so the on-chain helpers are agnostic.
    """
    if l1_key:
        evm_addr = eth_address_from_private_key(l1_key)
        pevm = ParadexEvm(
            env=env,
            evm_address=evm_addr,
            evm_private_key=l1_key,
            ws_enabled=False,
            server_derive_address=True,
        )
        account = pevm.account
        # Reads and fee estimates use unauthenticated RPC; invoke transactions
        # self-authenticate via their EIP-191 signature. Clearing the token keeps
        # contract reads on the public RPC path.
        account.jwt_token = None
        return account
    pclient = Paradex(env=env)
    return ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)


def _register_payload_for(
    public_key: str,
    name: str,
    env: str,
    sign: bool,
    l1_key: str | None,
    siwe_domain: str | None,
    chain_id: int | None,
) -> dict:
    """Build the register payload, choosing the stark-curve or EVM/SIWE
    authorization based on whether an L1 (Ethereum) key was supplied."""
    if l1_key:
        # EVM (EIP-191) main account: authorize via SIWE personal_sign.
        if siwe_domain is None or chain_id is None:
            d, c = evm_siwe_defaults(env)
            siwe_domain = siwe_domain or d
            chain_id = chain_id if chain_id is not None else c
        nonce = secrets.token_hex(16)
        return build_evm_register_payload(
            public_key,
            name,
            eth_private_key=l1_key,
            siwe_domain=siwe_domain,
            chain_id=chain_id,
            nonce=nonce,
        )
    # StarkNet main account: optional stark-curve authorization signature.
    # Only parse the L2 key when actually signing — without --sign the key is
    # not needed (and may be unset), so avoid converting it eagerly.
    private_key = int_16(ACCOUNT_KEY) if sign else None
    return build_register_payload(
        public_key,
        name,
        account_address=ACCOUNT_ADDRESS,
        private_key=private_key,
        sign=sign,
    )


def _register_subkey(
    public_key: str,
    name: str,
    env: str,
    sign: bool,
    l1_key: str | None = None,
    siwe_domain: str | None = None,
    chain_id: int | None = None,
) -> dict:
    # EVM accounts authenticate via the v2 SIWE flow; stark accounts via the
    # SDK's v1 flow. The authorization signature in the payload matches.
    if l1_key:
        pclient = _evm_authed_paradex(env, l1_key, siwe_domain, chain_id)
    else:
        pclient = _authed_paradex(env)
    payload = _register_payload_for(
        public_key, name, env, sign, l1_key, siwe_domain, chain_id
    )
    return pclient.api_client.post(
        api_url=pclient.api_client.api_url,
        path=SUBKEYS_PATH,
        payload=payload,
    )


@app.command()
def register_subkey(
    public_key: str = typer.Argument(..., help="StarkNet public key of the subkey to register"),
    name: str = typer.Option(..., "--name", help="User-friendly name for the subkey"),
    sign: bool = typer.Option(
        False,
        "--sign/--no-sign",
        help="StarkNet accounts: attach a main-key authorization signature "
        "(required when the backend enforces subkey-registration signatures).",
    ),
    l1_key: str = typer.Option(
        None,
        "--l1-key",
        envvar="PARADEX_L1_PRIVATE_KEY",
        help="EVM (EIP-191) accounts: the Ethereum private key of the main "
        "account. When set, authorizes registration via a SIWE personal_sign "
        "instead of a stark-curve signature.",
    ),
    siwe_domain: str = typer.Option(
        None, "--siwe-domain", help="Override the SIWE domain (default: per-env)."
    ),
    chain_id: int = typer.Option(
        None, "--chain-id", help="Override the EIP-155 chain id (default: per-env)."
    ),
    env: str = option_env,
):
    """
    Register a new trade-only subkey under the main account.

    The subkey can place and cancel orders but cannot deposit, withdraw,
    transfer, or manage keys. PARADEX_ACCOUNT_ADDRESS / PARADEX_ACCOUNT_KEY
    must be the main account.

    For a StarkNet main account, use --sign to attach a stark-curve
    authorization. For an EVM (EIP-191) main account, pass --l1-key (or
    PARADEX_L1_PRIVATE_KEY) to authorize via a SIWE personal_sign.
    """
    res = _register_subkey(public_key, name, env, sign, l1_key, siwe_domain, chain_id)
    print("Subkey registered:", public_key)
    if res:
        print(json.dumps(res, indent=2))


def _subkey_client(
    env: str, l1_key: str | None, siwe_domain: str | None, chain_id: int | None
) -> Paradex:
    """Authenticated client for subkey ops: EVM (v2 SIWE) when an L1 key is
    supplied, otherwise the StarkNet (v1) flow."""
    if l1_key:
        return _evm_authed_paradex(env, l1_key, siwe_domain, chain_id)
    return _authed_paradex(env)


# Shared EVM-auth options for the read/modify subkey commands.
_l1_key_opt = typer.Option(
    None, "--l1-key", envvar="PARADEX_L1_PRIVATE_KEY",
    help="EVM (EIP-191) main account: Ethereum private key, to authenticate via SIWE.",
)
_siwe_domain_opt = typer.Option(None, "--siwe-domain", help="Override SIWE domain (default: per-env).")
_chain_id_opt = typer.Option(None, "--chain-id", help="Override EIP-155 chain id (default: per-env).")


def _list_subkeys(env, with_revoked, l1_key=None, siwe_domain=None, chain_id=None) -> dict:
    pclient = _subkey_client(env, l1_key, siwe_domain, chain_id)
    params = {"with_revoked": "true"} if with_revoked else None
    return pclient.api_client.get(
        api_url=pclient.api_client.api_url, path=SUBKEYS_PATH, params=params
    )


@app.command()
def list_subkeys(
    with_revoked: bool = typer.Option(
        False, "--with-revoked", help="Include revoked subkeys in the listing"
    ),
    l1_key: str = _l1_key_opt,
    siwe_domain: str = _siwe_domain_opt,
    chain_id: int = _chain_id_opt,
    env: str = option_env,
):
    """List all subkeys registered under the main account."""
    res = _list_subkeys(env, with_revoked, l1_key, siwe_domain, chain_id)
    print(json.dumps(res, indent=2))


def _get_subkey(public_key, env, l1_key=None, siwe_domain=None, chain_id=None) -> dict:
    pclient = _subkey_client(env, l1_key, siwe_domain, chain_id)
    return pclient.api_client.get(
        api_url=pclient.api_client.api_url, path=f"{SUBKEYS_PATH}/{public_key}"
    )


@app.command()
def get_subkey(
    public_key: str = typer.Argument(..., help="Public key of the subkey to fetch"),
    l1_key: str = _l1_key_opt,
    siwe_domain: str = _siwe_domain_opt,
    chain_id: int = _chain_id_opt,
    env: str = option_env,
):
    """Fetch a single subkey by public key."""
    res = _get_subkey(public_key, env, l1_key, siwe_domain, chain_id)
    print(json.dumps(res, indent=2))


def _revoke_subkey(public_key, env, l1_key=None, siwe_domain=None, chain_id=None) -> dict:
    pclient = _subkey_client(env, l1_key, siwe_domain, chain_id)
    return pclient.api_client.delete(
        api_url=pclient.api_client.api_url, path=f"{SUBKEYS_PATH}/{public_key}"
    )


@app.command()
def revoke_subkey(
    public_key: str = typer.Argument(..., help="Public key of the subkey to revoke"),
    l1_key: str = _l1_key_opt,
    siwe_domain: str = _siwe_domain_opt,
    chain_id: int = _chain_id_opt,
    env: str = option_env,
):
    """
    Revoke a subkey. Subkeys can only be revoked using the main account.
    """
    res = _revoke_subkey(public_key, env, l1_key, siwe_domain, chain_id)
    print("Subkey revoked:", public_key)
    if res:
        print(json.dumps(res, indent=2))


def _update_subkey_allowed_cidrs(
    public_key, cidrs, env, l1_key=None, siwe_domain=None, chain_id=None
) -> dict:
    pclient = _subkey_client(env, l1_key, siwe_domain, chain_id)
    return pclient.api_client.put(
        api_url=pclient.api_client.api_url,
        path=f"{SUBKEYS_PATH}/{public_key}/allowed-cidrs",
        payload={"allowed_cidrs": cidrs},
    )


@app.command()
def update_subkey_allowed_cidrs(
    public_key: str = typer.Argument(..., help="Public key of the subkey to update"),
    cidr: list[str] = typer.Option(
        [],
        "--cidr",
        help="A CIDR to allow, e.g. 203.0.113.0/24. Repeat for multiple. "
        "The list fully replaces the previous one; pass no --cidr to clear "
        "the allowlist (make the subkey unrestricted).",
    ),
    l1_key: str = _l1_key_opt,
    siwe_domain: str = _siwe_domain_opt,
    chain_id: int = _chain_id_opt,
    env: str = option_env,
):
    """
    Replace the IP allowlist (CIDRs) for a subkey. The provided list fully
    replaces the previous one; an empty list makes the subkey unrestricted.
    """
    res = _update_subkey_allowed_cidrs(public_key, cidr, env, l1_key, siwe_domain, chain_id)
    print("Updated allowed CIDRs for subkey:", public_key)
    if res:
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    app()
