import base64
import json
from pathlib import Path
from web3 import Web3

web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))

# This resolves relative to THIS file's location, so it never breaks
# no matter which directory you run manage.py from.
CONTRACT_PATH = Path(__file__).resolve().parent.parent.parent / "blocks" / "build" / "contracts" / "Store.json"

with open(CONTRACT_PATH) as data:
    artifact = json.load(data)
    CONTRACT_ADDRESS = artifact["networks"]["5777"]["address"]
    CONTRACT_ABI = artifact["abi"]

contract_file = web3.eth.contract(abi=CONTRACT_ABI, address=CONTRACT_ADDRESS)

DEFAULT_ACCOUNT = web3.eth.accounts[1]
one = {"from": DEFAULT_ACCOUNT}


def addNewData(user: dict) -> dict:
    try:
        tx_hash = contract_file.functions.addString(
            base64.b64encode(json.dumps(user).encode()).decode()
        ).transact(one)
        
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "success": receipt.status == 1,
            "tx_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        }
    except Exception as e:
        return {
            "success": False,
            "tx_hash": None,
            "block_number": None,
            "gas_used": None,
            "error": str(e),
        }


def retrieveData() -> list | str:
    try:
        data = []
        variable = contract_file.functions.getAll().call(one)
        for i in variable:
            v = json.loads(base64.b64decode(i[1]).decode())
            v['sumID'] = i[0]
            data.append(v)
        return data
    except Exception as e:
        return f'{e}'


def updateData(position: int, data: dict) -> str:
    try:
        pp = base64.b64encode(json.dumps(data).encode()).decode()
        contract_file.functions.updateStore(position, pp).transact(one)
        return "Success"
    except Exception as e:
        return f'{e}'