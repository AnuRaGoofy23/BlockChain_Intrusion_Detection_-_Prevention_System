from web3 import Web3
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to Ganache or local testnet by default
BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:7545")

class BlockchainService:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
        
        # Load contract address
        contract_addr = os.getenv("THREAT_LOGGER_ADDRESS")
        if not contract_addr:
            try:
                addr_path = os.path.join(os.path.dirname(__file__), "contracts", "contract_address.json")
                if os.path.exists(addr_path):
                    with open(addr_path, "r") as f:
                        contract_addr = json.load(f).get("address")
            except Exception as e:
                print(f"Error loading contract address from JSON fallback: {e}")
        
        # Load ABI
        abi = None
        try:
            abi_path = os.path.join(os.path.dirname(__file__), "contracts", "ThreatLogger.json")
            if os.path.exists(abi_path):
                with open(abi_path, "r") as f:
                    abi = json.load(f).get("abi")
        except Exception as e:
            print(f"Error loading ThreatLogger ABI: {e}")
            
        self.contract = None
        if contract_addr and abi:
            try:
                self.contract_address = self.w3.to_checksum_address(contract_addr)
                self.contract = self.w3.eth.contract(address=self.contract_address, abi=abi)
                print(f"Successfully loaded ThreatLogger contract at address: {self.contract_address}")
            except Exception as e:
                print(f"Error initializing contract: {e}")
        else:
            print("ThreatLogger contract not initialized: contract address or ABI JSON is missing.")
    
    def is_connected(self):
        return self.w3.is_connected()
    
    def fetch_transaction_data(self, tx_hash: str):
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            # Basic fallback if tx not found
            if not tx:
                return None
            
            # Simple feature extraction
            gas_used = float(tx.get('gas', 21000))
            gas_price = float(tx.get('gasPrice', 20000000000)) # Default 20 Gwei
            gas_fee_eth = (gas_used * gas_price) / 1e18
            value_eth = float(self.w3.from_wei(tx.get('value', 0), 'ether'))
            to_address = tx.get('to')
            is_contract = 1 if not to_address else 0
            
            # For a single fetch, we can't easily compute block-level frequency without context
            # We'll default to 1. 
            tx_frequency = 1
            # Mocking failed tx ratio (0.0 to 1.0)
            failed_tx_ratio = 0.0 if gas_used < 100000 else 0.1
            
            # Extract permissions and token approvals
            tx_input = tx.get('input', '') or ''
            if isinstance(tx_input, bytes):
                tx_input_hex = tx_input.hex()
            else:
                tx_input_hex = str(tx_input)
                
            token_approval_amount = 0.0
            permissions = "None"
            
            if tx_input_hex.startswith('0x095ea7b3') or tx_input_hex.startswith('095ea7b3'):
                permissions = "Unlimited Approval"
                try:
                    amount_hex = tx_input_hex[74:138] if tx_input_hex.startswith('0x') else tx_input_hex[72:136]
                    if amount_hex:
                        amount_val = int(amount_hex, 16)
                        if amount_val > 10**27:
                            token_approval_amount = 999999999.0  # Represents Unlimited
                        else:
                            token_approval_amount = float(amount_val) / 1e18
                except Exception:
                    token_approval_amount = 1000000.0
            elif to_address is None:
                permissions = "Contract Creation"
            
            # Simulate wallet age and historical failures for this fetch
            wallet_age_days = 150 if gas_used < 100000 else 4
            failed_tx_count = 0 if gas_used < 100000 else 2
            
            return {
                "tx_hash": tx_hash,
                "gas_used": gas_used,
                "gas_fee_eth": gas_fee_eth,
                "value_eth": value_eth,
                "is_contract": is_contract,
                "tx_frequency": tx_frequency,
                "failed_tx_ratio": failed_tx_ratio,
                "from_address": tx.get('from'),
                "to_address": to_address,
                "wallet_age_days": wallet_age_days,
                "failed_tx_count": failed_tx_count,
                "permissions": permissions,
                "token_approval_amount": token_approval_amount
            }
        except Exception as e:
            print(f"Error fetching tx {tx_hash}: {e}")
            return None

    def get_latest_block_number(self):
        try:
            return self.w3.eth.block_number
        except Exception as e:
            print(f"Error fetching latest block number: {e}")
            return None

    def get_transactions_for_block(self, block_identifier='latest'):
        try:
            block = self.w3.eth.get_block(block_identifier, full_transactions=True)
            if not block or 'transactions' not in block:
                return []
            
            # Pre-compute frequencies
            address_counts = {}
            for tx in block.transactions:
                from_addr = tx.get('from')
                address_counts[from_addr] = address_counts.get(from_addr, 0) + 1
            
            extracted_txs = []
            for tx in block.transactions:
                tx_hash = tx.get('hash')
                if tx_hash:
                    tx_hash_hex = tx_hash.hex()
                    gas_used = float(tx.get('gas', 21000))
                    gas_price = float(tx.get('gasPrice', 20000000000))
                    gas_fee_eth = (gas_used * gas_price) / 1e18
                    value_eth = float(self.w3.from_wei(tx.get('value', 0), 'ether'))
                    to_addr = tx.get('to')
                    is_contract = 1 if not to_addr else 0
                    
                    from_addr = tx.get('from')
                    tx_frequency = address_counts.get(from_addr, 1)
                    
                    # Mock failed_tx_ratio based on gas and frequency for simulation
                    failed_tx_ratio = min(1.0, (tx_frequency * 0.05) + (0.1 if gas_used > 500000 else 0))
                    
                    tx_input = tx.get('input', '') or ''
                    if isinstance(tx_input, bytes):
                        tx_input_hex = tx_input.hex()
                    else:
                        tx_input_hex = str(tx_input)
                        
                    token_approval_amount = 0.0
                    permissions = "None"
                    
                    if tx_input_hex.startswith('0x095ea7b3') or tx_input_hex.startswith('095ea7b3'):
                        permissions = "Unlimited Approval"
                        try:
                            amount_hex = tx_input_hex[74:138] if tx_input_hex.startswith('0x') else tx_input_hex[72:136]
                            if amount_hex:
                                amount_val = int(amount_hex, 16)
                                if amount_val > 10**27:
                                    token_approval_amount = 999999999.0
                                else:
                                    token_approval_amount = float(amount_val) / 1e18
                        except Exception:
                            token_approval_amount = 1000000.0
                    elif to_addr is None:
                        permissions = "Contract Creation"
                        
                    wallet_age_days = 365 if gas_used < 200000 else 1
                    failed_tx_count = 0 if gas_used < 200000 else 5
                    
                    extracted_txs.append({
                        "tx_hash": tx_hash_hex,
                        "gas_used": gas_used,
                        "gas_fee_eth": gas_fee_eth,
                        "value_eth": value_eth,
                        "is_contract": is_contract,
                        "tx_frequency": tx_frequency,
                        "failed_tx_ratio": failed_tx_ratio,
                        "from_address": from_addr,
                        "to_address": to_addr,
                        "wallet_age_days": wallet_age_days,
                        "failed_tx_count": failed_tx_count,
                        "permissions": permissions,
                        "token_approval_amount": token_approval_amount
                    })
            return extracted_txs
        except Exception as e:
            print(f"Error fetching transactions for block {block_identifier}: {e}")
            return []

    def store_threat_log_on_blockchain(self, entity_type: str, value: str, description: str, severity: str) -> dict:
        """Stores a threat log on the blockchain by executing a transaction."""
        if not self.contract:
            raise ValueError("ThreatLogger contract is not initialized.")
        
        wallet_address = os.getenv("WALLET_ADDRESS")
        private_key = os.getenv("PRIVATE_KEY")
        
        if not wallet_address or not private_key:
            raise ValueError("WALLET_ADDRESS and PRIVATE_KEY environment variables must be set.")
            
        wallet_address = self.w3.to_checksum_address(wallet_address)
        if private_key.startswith("0x"):
            private_key = private_key[2:]
            
        nonce = self.w3.eth.get_transaction_count(wallet_address)
        
        tx = self.contract.functions.addThreat(
            entity_type,
            value,
            description,
            severity
        ).build_transaction({
            'from': wallet_address,
            'nonce': nonce,
            'gas': 500000,
            'gasPrice': self.w3.eth.gas_price,
            'chainId': self.w3.eth.chain_id
        })
        
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "tx_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "status": receipt.status
        }

    def fetch_threat_logs_from_blockchain(self) -> list:
        """Fetches all threat logs registered on the smart contract."""
        if not self.contract:
            print("ThreatLogger contract is not initialized.")
            return []
            
        try:
            count = self.contract.functions.threatCount().call()
            threats = []
            for i in range(1, count + 1):
                threat_data = self.contract.functions.getThreat(i).call()
                threats.append({
                    "id": threat_data[0],
                    "entity_type": threat_data[1],
                    "value": threat_data[2],
                    "description": threat_data[3],
                    "severity": threat_data[4],
                    "timestamp": threat_data[5],
                    "reporter": threat_data[6]
                })
            return threats
        except Exception as e:
            print(f"Error fetching threats from blockchain: {e}")
            return []

    def verify_threat_record_on_blockchain(self, id: int, value: str) -> bool:
        """Verifies if the threat record with the given ID matches the provided value."""
        if not self.contract:
            print("ThreatLogger contract is not initialized.")
            return False
            
        try:
            return self.contract.functions.verifyThreat(id, value).call()
        except Exception as e:
            print(f"Error verifying threat on blockchain: {e}")
            return False

blockchain_service = BlockchainService()

