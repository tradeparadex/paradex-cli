import asyncio
import json
import os
from typing import Any, Optional, Union

import typer
from starknet_py.cairo.felt import decode_shortstring
from starknet_py.contract import Contract
from starknet_py.net.account.account import _parse_calls
from starknet_py.net.client_models import Call
from starknet_py.net.models import parse_address
from starknet_py.net.models.chains import parse_chain
from starknet_py.net.models.transaction import Invoke, InvokeV1
from starknet_py.net.signer.stark_curve_signer import KeyPair

from paradex_cli.env_config import EnvConfig, env2config
from paradex_cli.helpers.account import Account, invoke_client

# Argent multisig backend spec - https://argenthq.notion.site/Argent-Multisig-Backend-1d7605a214fb8003863ae77e53ee4a41

# Create a state class for the multisig CLI
class State:
    env: str = ""
    account = None

    def get_config(self, env: Optional[str] = None):
        if env is not None:
            self.env = env
        return env2config[self.env]

    async def load_account(self):
        if self.account is None:
            cfg = self.get_config()
            if cfg.account_address is None:
                env_upper = cfg.env.upper()
                raise ValueError(
                    f"account_address is {cfg.account_address} for environment {env_upper}. "
                    f"Please set the {env_upper}_ACCOUNT_ADDRESS environment variable. "
                    f"Config: {cfg}"
                )

            chain_name = await cfg.client.get_chain_id()
            chain_id = parse_chain(chain_name)
            key_pair = None
            signer = None
            if os.environ.get("USE_LEDGER", "0") == "1":
                from starknet_py.net.signer.ledger_signer import LedgerSigner

                # https://github.com/argentlabs/argent-x/blob/13142607d83fea10b297d6a23452e810605784d1/packages/extension/src/shared/signer/derivationPaths.ts#L7
                # https://github.com/argentlabs/argent-x/blob/e3545daa417d6b60332b6112816d5e3b13c34358/packages/extension/src/shared/signer/derivationPaths.ts#L11
                # export const STANDARD_LEDGER_DERIVATION_PATH =
                #   "m/2645'/1195502025'/1148870696'/0'/0'"
                # export const MULTISIG_LEDGER_DERIVATION_PATH =
                #   "m/2645'/1195502025'/1148870696'/1'/0'"
                # starknetpy guide - "m/2645'/1195502025'/1470455285'/0'/0'/0"
                account_index = os.environ.get("LEDGER_ACCOUNT_INDEX", "0")
                ARGENT_STANDARD_LEDGER_DERIVATION_PATH = "m/2645'/1195502025'/1148870696'/0'/0'"
                # ARGENT_MULTISIG_LEDGER_DERIVATION_PATH = "m/2645'/1195502025'/1148870696'/1'/0'"
                # STARKNETPY_DERIVATION_PATH = "m/2645'/1195502025'/1470455285'/0'/0'"
                default_base_derivation_path = ARGENT_STANDARD_LEDGER_DERIVATION_PATH
                base_derivation_path = os.environ.get(
                    "LEDGER_DERIVATION_PATH", default_base_derivation_path
                )
                derivation_path = f"{base_derivation_path}/{account_index}"
                signer = LedgerSigner(
                    derivation_path_str=derivation_path,
                    chain_id=chain_id,
                )
                key_pair = None
            else:
                key_pair = KeyPair.from_private_key(
                    key=parse_address(cfg.account_private_key)
                )
            self.account = Account(
                client=cfg.client,
                address=cfg.account_address,
                signer=signer,
                key_pair=key_pair,
                chain=chain_id,
            )
            print(f"Account public key: {hex(self.account.signer.public_key)}")
        return self.account


# Create state instance
state = State()

# Create option for environment
option_env = typer.Option(
    "nightly", "--env", "-e", help="Environment to use: local, nightly, staging, testnet, prod"
)


# Set environment
def set_env(v: str) -> str:
    """Set the environment."""
    if v is None:
        return state.env
    return v


# Create a Typer instance for multisig commands
multisig_app = typer.Typer(name="multisig")


async def get_multisig_contract(cfg: EnvConfig, multisig_address: str) -> Contract:
    """Get a contract instance for the multisig account."""
    multisig_address = parse_address(multisig_address)
    contract = await Contract.from_address(address=multisig_address, provider=cfg.client)
    return contract


async def _change_threshold(cfg: EnvConfig, multisig_address: str, new_threshold: int):
    account = await state.load_account()
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Prepare the call
    calls = [multisig.functions["change_threshold"].prepare_invoke_v1(new_threshold=new_threshold)]
    prepared_invoke = await account.prepare_invoke(calls=calls)

    # Print message hash for signer validation
    print(
        f"Message hash to validate by signer: {hex(prepared_invoke.calculate_hash(chain_id=account._chain_id))}"
    )
    signature = account.signer.sign_transaction(prepared_invoke)
    signature = [account.signer.public_key, *signature]

    # Execute the transaction
    invoke_result = await account.invoke(multisig, prepared_invoke, signature)
    print(f"Transaction hash: {hex(invoke_result.hash)}")
    await account.client.wait_for_tx(invoke_result.hash)
    print(f"Threshold changed successfully to {new_threshold}")


async def _add_signers(
    cfg: EnvConfig, multisig_address: str, new_threshold: int, signers_to_add: list
):
    account = await state.load_account()
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Prepare the call
    calls = [
        multisig.functions["add_signers"].prepare_invoke_v1(
            new_threshold=new_threshold, signers_to_add=signers_to_add
        )
    ]

    prepared_invoke = await account.prepare_invoke(calls=calls)
    # Print message hash for signer validation
    print(
        f"Message hash to validate by signer: {hex(prepared_invoke.calculate_hash(chain_id=account._chain_id))}"
    )
    signature = account.signer.sign_transaction(prepared_invoke)
    signature = [account.signer.public_key, *signature]
    # Signer signs invoke payload
    invoke_result = await account.invoke(multisig, prepared_invoke, signature)

    print(f"Transaction hash: {hex(invoke_result.hash)}")
    await account.client.wait_for_tx(invoke_result.hash)
    print(f"Signers added successfully with new threshold {new_threshold}")


async def _remove_signers(
    cfg: EnvConfig, multisig_address: str, new_threshold: int, signers_to_remove: list
):
    account = await state.load_account()
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Prepare the call
    calls = [
        multisig.functions["remove_signers"].prepare_invoke_v1(
            new_threshold=new_threshold, signers_to_remove=signers_to_remove
        )
    ]
    prepared_invoke = await account.prepare_invoke(calls=calls, auto_estimate=True)

    # Print message hash for signer validation
    print(
        f"Message hash to validate by signer: {hex(prepared_invoke.calculate_hash(chain_id=account._chain_id))}"
    )
    sig_rs = account.signer.sign_transaction(prepared_invoke)
    signature = [account.signer.public_key, *sig_rs]

    # Execute the transaction
    invoke = await account.invoke(multisig, prepared_invoke, signature)
    print(f"Transaction hash: {hex(invoke.transaction_hash)}")
    await account.client.wait_for_tx(invoke.transaction_hash)
    print(f"Signers removed successfully with new threshold {new_threshold}")


async def _replace_signer(
    cfg: EnvConfig, multisig_address: str, signer_to_remove: int, signer_to_add: int
):
    account = await state.load_account()
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Prepare the call
    calls = [
        multisig.functions["replace_signer"].prepare_invoke_v1(
            signer_to_remove=signer_to_remove, signer_to_add=signer_to_add
        )
    ]
    prepared_invoke = await account.prepare_invoke(calls=calls, auto_estimate=True)

    # Print message hash for signer validation
    print(
        f"Message hash to validate by signer: {hex(prepared_invoke.calculate_hash(chain_id=account._chain_id))}"
    )
    sig_rs = account.signer.sign_transaction(prepared_invoke)
    signature = [account.signer.public_key, *sig_rs]
    # Execute the transaction
    invoke = await account.invoke(multisig, prepared_invoke, signature)
    print(f"Transaction hash: {hex(invoke.transaction_hash)}")
    await account.client.wait_for_tx(invoke.transaction_hash)
    print("Signer replaced successfully")


async def _get_multisig_info(cfg: EnvConfig, multisig_address: str):
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Get multisig information
    name = await multisig.functions["get_name"].call()
    name = decode_shortstring(tuple(name)[0])
    version_struct = await multisig.functions["get_version"].call()
    version_struct = tuple(version_struct)[0]
    version = f"{version_struct['major']}.{version_struct['minor']}.{version_struct['patch']}"
    threshold = await multisig.functions["get_threshold"].call()
    threshold = tuple(threshold)[0]
    signers = await multisig.functions["get_signers"].call()
    signers = tuple(signers)[0]
    # Print the information
    print(f"Multisig Name: {name}")
    print(f"Version: {version}")
    print(f"Threshold: {threshold}")
    print(f"Signers ({len(signers)}):")
    for i, signer in enumerate(signers):
        print(f"  {i+1}. {hex(signer)}")


async def _is_signer(cfg: EnvConfig, multisig_address: str, signer: int):
    multisig = await get_multisig_contract(cfg, multisig_address)

    result = await multisig.functions["is_signer"].call(signer=signer)
    if result:
        print(f"✅ {hex(signer)} is a signer of the multisig account {multisig_address}")
    else:
        print(f"❌ {hex(signer)} is NOT a signer of the multisig account {multisig_address}")


async def _verify_signature(
    cfg: EnvConfig,
    multisig_address: str,
    hash: int,
    signer: int,
    signature_r: int,
    signature_s: int,
):
    multisig = await get_multisig_contract(cfg, multisig_address)

    result = await multisig.functions["is_valid_signer_signature"].call(
        hash=hash, signer=signer, signature_r=signature_r, signature_s=signature_s
    )
    if result:
        print("✅ The signature is valid")
    else:
        print("❌ The signature is NOT valid")


def format_tx_for_signing(
    calls: list[Call], invoke_tx: Invoke, creator_signer: int, signature: list[int]
) -> str:
    """
    Format an Invoke for signing in JSON format.

    Args:
        invoke_tx: The prepared Invoke object
        creator: Creator address (if None, uses the sender address from the transaction)

    Returns:
        str: JSON-formatted transaction ready for signing
    """

    # Extract calls from the transaction
    formatted_calls = []
    for call in calls:
        formatted_calls.append(
            {
                "contractAddress": hex(call.to_addr),
                "entrypoint": hex(call.selector),
                "calldata": [hex(x) for x in call.calldata],
            }
        )

    # Format the transaction according to the specified JSON structure
    tx_format = {
        "starknetSignature": {"r": hex(signature[0]), "s": hex(signature[1])},
        "transaction": {
            "maxFee": hex(invoke_tx.max_fee),
            "version": hex(invoke_tx.version),
            "nonce": hex(invoke_tx.nonce),
            "calls": formatted_calls,
        },
        "creator": hex(creator_signer),
        "multisigAddress": hex(invoke_tx.sender_address),  # response
        "nonce": invoke_tx.nonce,  # response
    }

    # Return pretty-printed JSON
    return json.dumps(tx_format, indent=2)


def create_invoke_tx_from_json(
    json_data: Union[str, dict[str, Any]],
) -> Invoke:
    """
    Create an Invoke object from JSON format.

    Args:
        json_data: JSON string or dictionary with transaction data
        account: Account object to use as sender (optional)

    Returns:
        Invoke: The constructed transaction object
    """
    # Parse JSON if it's a string
    if isinstance(json_data, str):
        tx_data = json.loads(json_data)
    else:
        tx_data = json_data

    # Extract transaction data
    tx_info = tx_data.get("transaction", {})

    # Convert hex values to integers
    max_fee = int(tx_info.get("maxFee", "0x0"), 16)
    version = int(tx_info.get("version", "0x1"), 16)
    nonce = int(tx_info.get("nonce", "0x1"), 16)

    # Parse calls
    calls = []
    for call_data in tx_info.get("calls", []):
        contract_address = int(call_data.get("contractAddress", "0x0"), 16)
        entrypoint = int(call_data.get("entrypoint", "0x0"), 16)

        # Convert calldata hex values to integers
        calldata = [int(item, 16) for item in call_data.get("calldata", [])]

        # Create Call object
        call = Call(to_addr=contract_address, selector=entrypoint, calldata=calldata)
        calls.append(call)

    sender_address = parse_address(tx_data.get("multisigAddress", "0x0"))

    calldata = _parse_calls(version, calls)
    # Create Invoke
    invoke_tx = InvokeV1(
        calldata=calldata,
        max_fee=max_fee,
        version=version,
        nonce=nonce,
        sender_address=sender_address,
        signature=[],
    )

    return invoke_tx


# Register Typer command functions
@multisig_app.command(help="Change the threshold for a multisig account.")
def change_threshold(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    new_threshold: int = typer.Argument(..., help="New threshold value"),
    env: str = option_env,
):
    """Change the threshold for a multisig account."""
    state.env = set_env(env)
    asyncio.run(_change_threshold(state.get_config(), multisig_address, new_threshold))


@multisig_app.command(help="Add signers to a multisig account.")
def add_signers(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    new_threshold: int = typer.Argument(..., help="New threshold value after adding signers"),
    signers: str = typer.Argument(..., help="Comma-separated list of signer addresses to add"),
    env: str = option_env,
):
    """Add signers to a multisig account."""
    state.env = set_env(env)
    signer_list = [parse_address(s.strip()) for s in signers.split(",")]
    asyncio.run(_add_signers(state.get_config(), multisig_address, new_threshold, signer_list))


@multisig_app.command(help="Remove signers from a multisig account.")
def remove_signers(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    new_threshold: int = typer.Argument(..., help="New threshold value after removing signers"),
    signers: str = typer.Argument(..., help="Comma-separated list of signer addresses to remove"),
    env: str = option_env,
):
    """Remove signers from a multisig account."""
    state.env = set_env(env)
    signer_list = [parse_address(s.strip()) for s in signers.split(",")]
    asyncio.run(_remove_signers(state.get_config(), multisig_address, new_threshold, signer_list))


@multisig_app.command(help="Replace a signer in a multisig account.")
def replace_signer(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    old_signer: str = typer.Argument(..., help="Address of the signer to remove"),
    new_signer: str = typer.Argument(..., help="Address of the signer to add"),
    env: str = option_env,
):
    """Replace a signer in a multisig account."""
    state.env = set_env(env)
    asyncio.run(
        _replace_signer(
            state.get_config(),
            multisig_address,
            parse_address(old_signer),
            parse_address(new_signer),
        )
    )


@multisig_app.command(help="Get information about a multisig account.")
def get_info(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    env: str = option_env,
):
    """Get information about a multisig account."""
    state.env = set_env(env)
    asyncio.run(_get_multisig_info(state.get_config(), multisig_address))


@multisig_app.command(help="Check if an address is a signer of a multisig account.")
def is_signer(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    signer: str = typer.Argument(..., help="Address to check"),
    env: str = option_env,
):
    """Check if an address is a signer of a multisig account."""
    state.env = set_env(env)
    asyncio.run(_is_signer(state.get_config(), multisig_address, parse_address(signer)))


@multisig_app.command(help="Verify a signature from a multisig signer.")
def verify_signature(
    multisig_address: str = typer.Argument(..., help="Multisig account address"),
    hash: str = typer.Argument(..., help="Hash that was signed"),
    signer: str = typer.Argument(..., help="Address of the signer"),
    signature_r: str = typer.Argument(..., help="r component of the signature"),
    signature_s: str = typer.Argument(..., help="s component of the signature"),
    env: str = option_env,
):
    """Verify a signature from a multisig signer."""
    state.env = set_env(env)
    asyncio.run(
        _verify_signature(
            state.get_config(),
            multisig_address,
            parse_address(hash),
            parse_address(signer),
            parse_address(signature_r),
            parse_address(signature_s),
        )
    )


async def _sign_transaction_from_file(cfg: EnvConfig, file_path: str):
    """Sign a transaction loaded from a JSON file."""
    account = await state.load_account()

    # Load transaction JSON from file
    with open(file_path) as f:
        tx_json = json.load(f)

    # Create invoke transaction from JSON
    invoke_tx = create_invoke_tx_from_json(tx_json)

    # Calculate transaction hash for signature
    chain_id = account._chain_id
    tx_hash = invoke_tx.calculate_hash(chain_id=chain_id)
    print(f"Message hash to validate by signer: {hex(tx_hash)}")
    # Sign the transaction
    signature = account.signer.sign_transaction(invoke_tx)

    # Format the output
    output = {
        "starknetSignature": {"r": hex(signature[0]), "s": hex(signature[1])},
        "signer": hex(account.signer.public_key),
    }

    # Print the formatted output
    print(json.dumps(output, indent=2))

    return output


async def _submit_transaction(cfg: EnvConfig, file_path: str):
    """
    Load transaction and signatures from file, check if number of approved signers > threshold,
    prepare tx and submit it with signatures.

    Args:
        cfg: Environment configuration
        file_path: Path to the JSON file containing the transaction and signatures
    """
    # Load transaction JSON from file
    with open(file_path) as f:
        tx_data = json.load(f)

    # Get multisig information
    content = tx_data.get("content", tx_data)  # Handle both root level and content object
    multisig_address = content.get("multisigAddress")
    if not multisig_address:
        raise ValueError("Multisig address not found in the transaction file")

    # Get multisig contract
    multisig = await get_multisig_contract(cfg, multisig_address)

    # Get the threshold
    threshold_result = await multisig.functions["get_threshold"].call()
    threshold = tuple(threshold_result)[0]

    # Check if enough signers have approved
    approved_signers = content.get("approvedSigners", [])
    # Sort approved signers by their integer value
    # https://github.com/argentlabs/argent-contracts-starknet/blob/multisig-0.1.1/src/multisig/README.md#signature-format
    approved_signers.sort(key=lambda x: int(x, 16))
    if len(approved_signers) < threshold:
        print(
            f"❌ Not enough signers have approved. Required: {threshold}, Approved: {len(approved_signers)}"
        )
        return

    print(
        f"✅ Sufficient signers ({len(approved_signers)}/{threshold}) have approved the transaction"
    )

    # Use create_invoke_tx_from_json to parse the transaction data
    tx_info = content.get("transaction", {})
    invoke_tx = create_invoke_tx_from_json({"transaction": tx_info})

    # InvokeV1 is a frozen dataclass, need to create a new instance with the updated sender_address
    invoke_tx = InvokeV1(
        calldata=invoke_tx.calldata,
        max_fee=invoke_tx.max_fee,
        version=invoke_tx.version,
        nonce=invoke_tx.nonce,
        sender_address=parse_address(multisig_address),
        signature=[],
    )

    # In the multisig we need the signatures from the signers
    # The format should include signatures for approved signers
    # We'll look for a signatures field in the transaction data
    signatures = tx_data.get("signatures", {})

    # If signatures aren't directly in the file, ask the user to provide them
    if not signatures:
        print("⚠️ No signatures found in the transaction file.")
        print("Please provide signatures for each approved signer in the format:")
        print("{signer_address: {r: '0x...', s: '0x...'}}")

        # In a real implementation, you might want to prompt for signatures here
        # For now, we'll show an error
        print("❌ Cannot proceed without signatures")
        return

    # Process each approved signer (up to threshold)
    signers_list = []
    signatures_list = []
    for signer in approved_signers[:threshold]:
        signer_address = parse_address(signer)
        signers_list.append(signer_address)

        # Get signature for this signer
        signer_signature = signatures.get(signer, None)
        if not signer_signature:
            print(f"❌ Missing signature for signer {signer}")
            return

        # Extract r and s values
        r_value = int(signer_signature.get("r", "0x0"), 16)
        s_value = int(signer_signature.get("s", "0x0"), 16)

        signatures_list.extend([signer_address, r_value, s_value])

    # Call the execute function on the multisig contract
    try:

        # Send the transaction directly using account.invoke with the prepared call and signatures
        print(f"Submitting transaction with {len(signers_list)} signatures...")
        print(f"Signatures: {signatures_list}")
        print(f"Invoke tx: {invoke_tx}")
        print(f"Multisig: {multisig}")
        # We can use the account.invoke method with the contract address, call, and signatures
        invoke_result = await invoke_client(
            client=cfg.client,
            contract=multisig,
            prepared_invoke=invoke_tx,
            signature=signatures_list,
        )

        print(f"Transaction hash: {hex(invoke_result.hash)}")
        await cfg.client.wait_for_tx(invoke_result.hash)
        print("✅ Transaction executed successfully")
    except Exception as e:
        print(f"❌ Failed to execute transaction: {e}")
        # Print more detailed error information if available
        import traceback

        traceback.print_exc()


@multisig_app.command(help="Sign a transaction loaded from a JSON file.")
def sign_transaction(
    file_path: str = typer.Argument(..., help="Path to the transaction JSON file"),
    env: str = option_env,
):
    """Sign a transaction loaded from a JSON file and output the signature."""
    state.env = set_env(env)
    asyncio.run(_sign_transaction_from_file(state.get_config(), file_path))


async def _merge_signatures(
    cfg: EnvConfig, tx_file_path: str, signature_files: list[str], output_file_path: str
):
    """
    Merge multiple signature files with a transaction file to create a transaction file ready for submission.

    Args:
        cfg: Environment configuration
        tx_file_path: Path to the original transaction JSON file
        signature_files: List of paths to signature files generated by sign_transaction
        output_file_path: Path to write the merged transaction file
    """
    # Load transaction JSON from file
    if not os.path.exists(tx_file_path):
        raise FileNotFoundError(f"Transaction file not found: {tx_file_path}")
    with open(tx_file_path) as f:
        tx_data = json.load(f)

    # Extract multisig address from transaction
    multisig_address = None

    # Check if the transaction contains a multisigAddress directly or under content
    if "multisigAddress" in tx_data:
        multisig_address = tx_data["multisigAddress"]
    elif "content" in tx_data and "multisigAddress" in tx_data["content"]:
        multisig_address = tx_data["content"]["multisigAddress"]

    if not multisig_address:
        # If we still don't have a multisig address, prompt for it
        print("⚠️ Multisig address not found in the transaction file.")
        multisig_address_input = input("Please enter the multisig address: ")
        multisig_address = multisig_address_input.strip()

    # Ensure we have a valid multisig_address
    if not multisig_address:
        raise ValueError("Multisig address is required to merge signatures")

    # Prepare the output structure
    merged_data = {
        "multisigAddress": multisig_address,
        "transaction": tx_data.get("transaction", {}),
        "approvedSigners": [],
        "signatures": {},
    }

    if "creator" in tx_data:
        creator_signer = tx_data["creator"]
        creator_signature = tx_data["starknetSignature"]
        merged_data["approvedSigners"].append(creator_signer)
        merged_data["signatures"][creator_signer] = creator_signature

    # Load and merge each signature file
    for sig_file in signature_files:
        if not os.path.exists(sig_file):
            print(f"⚠️ Warning: Signature file not found: {sig_file}. Skipping.")
            continue
        with open(sig_file) as f:
            sig_data = json.load(f)

        # Extract signer and signature
        if "signer" in sig_data and "starknetSignature" in sig_data:
            signer = sig_data["signer"]
            signature = sig_data["starknetSignature"]

            # Add to approved signers if not already there
            if signer not in merged_data["approvedSigners"]:
                merged_data["approvedSigners"].append(signer)

            # Add signature
            merged_data["signatures"][signer] = signature

    # Ensure creator is included if present in original tx
    if "creator" in tx_data:
        merged_data["creator"] = tx_data["creator"]

    # Write the merged file
    with open(output_file_path, "w") as f:
        json.dump(obj=merged_data, indent=2, sort_keys=False, fp=f)

    print(
        f"✅ Created merged transaction file with {len(merged_data['approvedSigners'])} signatures at {output_file_path}"
    )
    print(f"Run 'submit_transaction {output_file_path}' to execute the transaction")


@multisig_app.command(
    help="Merge multiple signature files with a transaction file for submission."
)
def merge_signatures(
    tx_file_path: str = typer.Argument(..., help="Path to the original transaction JSON file"),
    signature_files: str = typer.Argument(
        ..., help="Comma-separated list of signature file paths"
    ),
    output_file_path: str = typer.Argument(..., help="Path to write the merged transaction file"),
    env: str = option_env,
):
    """
    Merge multiple signature files with a transaction file to create a transaction ready for submission.

    This command takes an original transaction file (same format used for sign_transaction)
    and a list of signature files (outputs from sign_transaction), and combines them into
    a single file that can be used with submit_transaction.

    Example usage:
        merge_signatures tx.json "sig1.json,sig2.json,sig3.json" merged_tx.json

    Args:
        tx_file_path: Path to the original transaction JSON file
        signature_files: Comma-separated list of paths to signature files
        output_file_path: Path to write the merged transaction file
        env: Environment to use (local, nightly, staging, testnet, prod)
    """
    state.env = set_env(env)
    sig_files_list = [f.strip() for f in signature_files.split(",")]
    asyncio.run(
        _merge_signatures(state.get_config(), tx_file_path, sig_files_list, output_file_path)
    )


@multisig_app.command(help="Submit a transaction with signatures from a file.")
def submit_transaction(
    file_path: str = typer.Argument(..., help="Path to the transaction JSON file with signatures"),
    env: str = option_env,
):
    """
    Submit a transaction with signatures from a file.

    This command loads a transaction and signatures from a JSON file, checks if the number
    of approved signers is greater than the threshold of the multisig, and if so,
    submits the transaction with the provided signatures.

    The file should be in a format similar to Argent's multisig backend format, which
    includes fields like multisigAddress, approvedSigners, transaction details, and
    signatures. The command supports various signature formats:

    1. Direct signatures object with signer keys and r/s values
    2. Approved signatures with signer/signature pairs
    3. Content object with approved signers and embedded signatures
    4. StarknetSignature with creator field

    If the command can't find signatures in the expected formats, it will prompt
    for manual input.

    Args:
        file_path: Path to the JSON file containing the transaction and signatures
        env: Environment to use (local, nightly, staging, testnet, prod)
    """
    state.env = set_env(env)
    asyncio.run(_submit_transaction(state.get_config(), file_path))
