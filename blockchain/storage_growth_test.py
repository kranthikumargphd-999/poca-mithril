import json
import time
from pathlib import Path
from web3 import Web3


# ======================================
# GANACHE CONNECTION
# ======================================

RPC_URL = "http://127.0.0.1:7545"

web3 = Web3(
    Web3.HTTPProvider(RPC_URL)
)


if not web3.is_connected():
    print("Ganache connection failed")
    exit()


print("==============================")
print("Storage Growth Test")
print("==============================")


# ======================================
# LOAD CONTRACT
# ======================================

CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent
    / "blocks"
    / "build"
    / "contracts"
    / "Store.json"
)


with open(CONTRACT_PATH, "r") as file:
    artifact = json.load(file)


CONTRACT_ABI = artifact["abi"]

CONTRACT_ADDRESS = artifact["networks"]["5777"]["address"]


contract = web3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=CONTRACT_ABI
)


ACCOUNT = web3.eth.accounts[0]


print("Contract:")
print(CONTRACT_ADDRESS)

print("Account:")
print(ACCOUNT)



# ======================================
# TEST SETTINGS
# ======================================

PROOF_COUNTS = [
    100,
    500,
    1000,
    5000,
    10000
]


# ======================================
# STORAGE TEST
# ======================================


for count in PROOF_COUNTS:

    print("\n==============================")
    print("Adding proofs:", count)
    print("==============================")


    success = 0
    failed = 0
    total_gas = 0


    start_time = time.time()


    # get current nonce
    nonce = web3.eth.get_transaction_count(
        ACCOUNT,
        "pending"
    )


    for i in range(count):

        try:

            proof_data = {
                "proof_id": i,
                "hash": "POCA_HASH_" + str(i),
                "time": time.time()
            }


            data = json.dumps(
                proof_data
            )


            transaction = (
                contract
                .functions
                .addString(data)
                .build_transaction(
                    {
                        "from": ACCOUNT,
                        "nonce": nonce,
                        "gas": 500000,
                        "gasPrice": web3.eth.gas_price
                    }
                )
            )


            tx_hash = web3.eth.send_transaction(
                transaction
            )


            receipt = (
                web3.eth
                .wait_for_transaction_receipt(
                    tx_hash
                )
            )


            nonce += 1


            if receipt.status == 1:

                success += 1

                total_gas += receipt.gasUsed


            else:

                failed += 1



        except Exception as e:

            failed += 1

            print(
                "Failed:",
                i,
                e
            )


            # refresh nonce after failure
            nonce = web3.eth.get_transaction_count(
                ACCOUNT,
                "pending"
            )



    end_time = time.time()


    execution_time = (
        end_time -
        start_time
    )


    avg_gas = (
        total_gas / success
        if success > 0
        else 0
    )


    print("\nRESULT")

    print(
        "Successful:",
        success
    )

    print(
        "Failed:",
        failed
    )

    print(
        "Execution Time:",
        round(
            execution_time,
            3
        ),
        "seconds"
    )

    print(
        "Average Gas:",
        round(
            avg_gas,
            2
        )
    )


print("\n==============================")
print("Storage Growth Test Completed")
print("==============================") 