import asyncio
import dataclasses
import json
import os
import re
import sys
from decimal import Decimal
from typing import Callable, Optional, Union

import marshmallow_dataclass
import typer
from Crypto.Random import get_random_bytes
from paradex_py.account.starknet import Account as StarknetAccount
from paradex_py.paradex import Paradex, ParadexAccount
from paradex_py.utils import random_max_fee
from starknet_py.cairo.felt import decode_shortstring
from starknet_py.contract import Contract
from starknet_py.net.models import AddressRepresentation, InvokeV1
from starknet_py.net.signer.stark_curve_signer import KeyPair
from starknet_py.proxy.contract_abi_resolver import ProxyConfig
from starknet_py.proxy.proxy_check import ArgentProxyCheck, OpenZeppelinProxyCheck, ProxyCheck
from starknet_py.net.models import Address, AddressRepresentation, InvokeV1
from starknet_py.net.client import Client
from starknet_py.constants import RPC_CONTRACT_ERROR
from starknet_py.net.client_errors import ClientError
from starknet_py.net.client_models import Call
from starknet_py.hash.selector import get_selector_from_name


app = typer.Typer(
    help="""Manage account contract setup.
    - Print account info
    - Add guardian
    - Add guardian backup
    - Change signer
    - Sign invoke tx
    - Submit invoke tx
    - Withdraw to L1
    - Transfer on L2
    - Deposit to Paraclear
    """,
    # rich_markup_mode="rich",
)
option_env = typer.Option("testnet", help="local, nightly, staging, testnet, prod")


@app.callback()
def check_env_vars():
    """
    Check if required environment variables are set.
    """
    required_vars = ["PARADEX_ACCOUNT_ADDRESS", "PARADEX_ACCOUNT_KEY"]
    missing_vars = [var for var in required_vars if var not in os.environ]

    if missing_vars:
        typer.echo(f"Missing required environment variables: {', '.join(missing_vars)}", err=True)
        raise typer.Exit(code=1)


# Accounts for Private StarkNet
ACCOUNT_ADDRESS = os.environ.get("PARADEX_ACCOUNT_ADDRESS")
ACCOUNT_KEY = os.environ.get("PARADEX_ACCOUNT_KEY")

# export PSN_FULL_NODE_URL = "https://juno.api.prod.paradex.trade/rpc/v0_7"
# export PSN_CHAIN_NAME = PRIVATE_SN_PARACLEAR_MAINNET
# https://github.com/argentlabs/argent-contracts-starknet/blob/main/src/account/README.md


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
    contract = await Contract.from_address(
        address=address, provider=account.starknet, proxy_config=proxy_config
    )
    return contract


def print_invoke(invoke: InvokeV1, file=sys.stdout):
    invoke_schema = marshmallow_dataclass.class_schema(InvokeV1)()
    print(invoke_schema.dumps(invoke), file=file)


def load_invoke(file) -> InvokeV1:
    invoke_schema = marshmallow_dataclass.class_schema(InvokeV1)()
    invoke: InvokeV1 = invoke_schema.loads(file.read().strip())
    # Needed because `calldata` marshmallow_field is fields.String()
    calldata = list(map(lambda v: int(v), invoke.calldata))
    invoke = dataclasses.replace(invoke, calldata=calldata)
    return invoke


def load_signature(file) -> list[int]:
    return json.loads(file.read().strip())


async def _change_signer(saccount: StarknetAccount, contract: Contract, pub_key: str):
    need_multisig = await _check_multisig_required(contract)

    print("Change signer...")
    funcName = 'changeGuardian'
    call = contract.functions[funcName].prepare_invoke_v1(
        newGuardian=int_16(pub_key),
        max_fee=random_max_fee(),
    )
    prepared_invoke = await saccount.prepare_invoke(calls=call, max_fee=random_max_fee())
    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _change_guardian(saccount: StarknetAccount, contract: Contract, guardian_pub_key: str):

    need_multisig = await _check_multisig_required(contract)

    print("Change guardian...")
    funcName = 'changeGuardian'
    call = contract.functions[funcName].prepare_invoke_v1(
        newGuardian=int_16(guardian_pub_key),
        max_fee=random_max_fee(),
    )
    prepared_invoke = await saccount.prepare_invoke(calls=call, max_fee=random_max_fee())
    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _change_guardian_backup(saccount: StarknetAccount, contract: Contract, pub_key: str):
    need_multisig = await _check_multisig_required(contract)

    print("Change guardian backup...")
    funcName = 'changeGuardianBackup'
    call = contract.functions[funcName].prepare_invoke_v1(
        newGuardian=int_16(pub_key),
        max_fee=random_max_fee(),
    )
    prepared_invoke = await saccount.prepare_invoke(calls=call, max_fee=random_max_fee())

    await _process_invoke(saccount, contract, need_multisig, prepared_invoke, funcName)


async def _check_multisig_required(contract: Contract):
    get_signer_call = await contract.functions["getSigner"].call()
    print("Current signer:", hex(get_signer_call.signer))

    get_guardian_call = await contract.functions["getGuardian"].call()
    current_guardian = get_guardian_call.guardian
    print("Current guardian:", hex(current_guardian))

    get_guardian_call = await contract.functions["getGuardianBackup"].call()
    current_guardian_backup = get_guardian_call.guardianBackup
    print("Current guardian backup:", hex(current_guardian_backup))

    need_multisig = False
    if current_guardian_backup != 0 or current_guardian != 0:
        need_multisig = True
    return need_multisig


async def _process_invoke(
    saccount: StarknetAccount,
    contract: Contract,
    need_multisig,
    prepared_invoke: InvokeV1,
    multisig_filename: str,
):
    if not need_multisig:
        # Signer signs invoke payload
        owner_signature = saccount.signer.sign_transaction(prepared_invoke)
        # Invoke contract function with signatures
        invoke_result = await saccount.invoke(contract, prepared_invoke, owner_signature)
        print("Waiting tx hash:", hex(invoke_result.hash))
        await invoke_result.wait_for_acceptance()
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
    name = await contract.functions["getName"].call()
    print("Name:", decode_shortstring(name.name))

    version = await contract.functions["getVersion"].call()
    print("Version:", decode_shortstring(version.version))

    get_signer_call = await contract.functions["getSigner"].call()
    print("Current signer pubkey:", hex(get_signer_call.signer))

    get_guardian_call = await contract.functions["getGuardian"].call()
    print("Current guardian pubkey:", hex(get_guardian_call.guardian))

    get_guardian_call = await contract.functions["getGuardianBackup"].call()
    print("Current guardian backup pubkey:", hex(get_guardian_call.guardianBackup))


async def _fetch_signers_pubkeys(contract: Contract) -> list[int]:
    get_signer_call = await contract.functions["getSigner"].call()
    get_guardian_call = await contract.functions["getGuardian"].call()
    get_guardian_backup_call = await contract.functions["getGuardianBackup"].call()
    return [
        hex(get_signer_call.signer),
        hex(get_guardian_call.guardian),
        hex(get_guardian_backup_call.guardianBackup),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    contract = asyncio.run(load_contract_from_account(int_16(acc), paccount))
    asyncio.run(_print_account_info(contract))


@app.command()
def add_guardian_backup(
    pub_key: str = typer.Argument(default=None, help="Public key of the guardian backup to add"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    if pub_key is None:
        guardian_backup_key_file = "guardian_backup.key"
        print("Generating guardian pubkey...")
        if os.path.exists(guardian_backup_key_file):
            private = KeyPair.from_private_key(open(guardian_backup_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + get_random_bytes(32).hex())
            with open(guardian_backup_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_guardian_backup(paccount.starknet, contract, pub_key))


@app.command()
def add_guardian(
    pub_key: str = typer.Argument(..., help="Public key of the guardian to add"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    if pub_key is None:
        print("Generating guardian pubkey...")
        guardian_key_file = "guardian.key"
        if os.path.exists(guardian_key_file):
            private = KeyPair.from_private_key(open(guardian_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + get_random_bytes(32).hex())
            with open(guardian_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_guardian(paccount.starknet, contract, pub_key))


@app.command()
def change_signer(
    pub_key: str = typer.Argument(..., help="Public key of the signer to replace"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    if pub_key is None:
        print("Generating signer pubkey...")
        guardian_key_file = "signer.key"
        if os.path.exists(guardian_key_file):
            private = KeyPair.from_private_key(open(guardian_key_file).read())
        else:
            private = KeyPair.from_private_key("0x" + get_random_bytes(32).hex())
            with open(guardian_key_file, "w") as file:
                file.write(hex(private.private_key))
        pub_key = hex(private.public_key)
    contract = asyncio.run(load_contract_from_account(paccount.l2_address, paccount))
    print("Contract address:", hex(paccount.l2_address))
    asyncio.run(_change_signer(paccount.starknet, contract, pub_key))


@app.command()
def sign_invoke_tx(
    file_path: str = typer.Argument(..., help="Filepath to invoke tx json"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    asyncio.run(_sign_invoke_tx(paccount, file_path))


@app.command()
def submit_invoke_tx(
    tx_file_path: str = typer.Argument(..., help="File with invoke transaction"),
    sig_files: list[str] = typer.Argument(..., help="Files with signatures"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    asyncio.run(_submit_invoke_tx(paccount, tx_file=tx_file_path, sig_files=sig_files))


async def _withdraw_to_l1(paccount: ParadexAccount, l1_recipient: str, amount_decimal: Decimal):
    paraclear_address = paccount.config.paraclear_address
    usdc_address = paccount.config.bridged_tokens[0].l2_token_address

    account_contract = await load_contract_from_account(
        address=paccount.l2_address, account=paccount
    )
    paraclear_contract = await load_contract_from_account(
        address=paraclear_address, account=paccount
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
    print(f"USDC Bridge Contract: {l2_bridge_contract}")

    token_asset_bal = await paraclear_contract.functions["getTokenAssetBalance"].call(
        account=paccount.l2_address, token_address=int_16(usdc_address)
    )
    print(f"USDC balance on paraclear: {token_asset_bal.balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to withdraw from paraclear: {amount_paraclear}")
    amount_bridge = int(amount_decimal * 10**usdc_decimals)
    print(f"Amount to withdraw from bridge: {amount_bridge}")

    l1_recipient_arg = int_16(l1_recipient)
    l1_recipient_arg = (
        {"address": l1_recipient_arg} if l2_bridge_version == 2 else l1_recipient_arg
    )
    calls = [
        paraclear_contract.functions["withdraw"].prepare_invoke_v1(
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
        l2_bridge_contract.functions["initiate_withdraw"].prepare_invoke_v1(
            l1_recipient=l1_recipient_arg,
            amount=amount_bridge,
        ),
    ]
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'withdrawToL1'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, max_fee=random_max_fee())

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def withdraw_to_l1(
    l1_address: str = typer.Argument(..., help="L1 address to transfer to"),
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
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
        address=paraclear_address, account=paccount
    )
    print(f"Paraclear Contract: {paraclear_address}")
    paraclear_decimals = paccount.config.paraclear_decimals

    usdc_contract = await load_contract_from_account(
        address=usdc_address, account=paccount
    )
    usdc_decimals = paccount.config.bridged_tokens[0].decimals

    token_asset_bal = await paraclear_contract.functions["getTokenAssetBalance"].call(
        account=paccount.starknet.address, token_address=int_16(usdc_address)
    )
    print(f"USDC balance on paraclear: {token_asset_bal.balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to withdraw from paraclear: {amount_paraclear}")
    amount_bridge = int(amount_decimal * 10**usdc_decimals)
    print(f"Amount to transfer to {target_l2_address}: {amount_bridge}")
    calls = [
        paraclear_contract.functions["withdraw"].prepare_invoke_v1(
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
        usdc_contract.functions["increase_allowance"].prepare_invoke_v1(
            spender=int_16(paraclear_address), added_value=amount_bridge
        ),
        paraclear_contract.functions["deposit_on_behalf_of"].prepare_invoke_v1(
            recipient=int_16(target_l2_address),
            token_address=int_16(usdc_address),
            amount=amount_paraclear,
        ),
    ]
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'transferOnL2'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, max_fee=random_max_fee())

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def transfer_on_l2(
    l2_address: str = typer.Argument(..., help="L2 address to transfer to"),
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
    env: str = option_env,
):
    """
    Withdraw balance from Paraclear and transfer to different account on L2

    Args:
        l2_address (str): The L2 address to transfer the balance to.
        amount_decimal (str): The amount to transfer.
        env (str): The environment to use for the transfer.

    """
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    asyncio.run(_transfer_on_l2(paccount, l2_address, Decimal(amount_decimal)))


async def _deposit_to_paraclear(paccount: ParadexAccount, amount_decimal: Decimal):

    paraclear_address = paccount.config.paraclear_address
    usdc_address = paccount.config.bridged_tokens[0].l2_token_address

    account_contract = await load_contract_from_account(
        address=paccount.l2_address, account=paccount
    )
    paraclear_contract = await load_contract_from_account(
        address=paraclear_address, account=paccount
    )
    print(f"Paraclear Contract: {paraclear_address}")
    paraclear_decimals = paccount.config.paraclear_decimals

    usdc_contract = await load_contract_from_account(
        address=usdc_address, account=paccount
    )
    usdc_decimals = paccount.config.bridged_tokens[0].decimals
    print(f"usdc_address: {usdc_address}")
    token_asset_bal = await paraclear_contract.functions["getTokenAssetBalance"].call(
        account=paccount.l2_address, token_address=int_16(usdc_address)
    )
    print(f"USDC balance on paraclear: {token_asset_bal.balance / 10**paraclear_decimals}")
    amount_paraclear = int(amount_decimal * 10**paraclear_decimals)
    print(f"Amount to deposit to paraclear: {amount_paraclear}")
    amount_usdc = int(amount_decimal * 10**usdc_decimals)
    increase_allowance_func_name = (
        "increase_allowance"
        if "increase_allowance" in usdc_contract.functions
        else "increaseAllowance"
    )
    calls = [
        usdc_contract.functions[increase_allowance_func_name].prepare_invoke_v1(
            spender=int_16(paraclear_address), added_value=amount_usdc
        ),
        paraclear_contract.functions["deposit"].prepare_invoke_v1(
            int_16(usdc_address), amount_paraclear
        ),
    ]
    need_multisig = await _check_multisig_required(account_contract)

    funcName = 'depositToParaclear'
    prepared_invoke = await paccount.starknet.prepare_invoke(calls=calls, max_fee=random_max_fee())

    await _process_invoke(
        paccount.starknet, account_contract, need_multisig, prepared_invoke, funcName
    )


@app.command()
def deposit_to_paraclear(
    amount_decimal: str = typer.Argument(..., help="Amount to transfer"),
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
    pclient = Paradex(env=env)
    paccount = ParadexAccount(config=pclient.config, l1_address="0x0", l2_private_key=ACCOUNT_KEY)
    asyncio.run(_deposit_to_paraclear(paccount, Decimal(amount_decimal)))


if __name__ == "__main__":
    app()
