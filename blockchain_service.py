from web3 import Web3
import os

# Connect to Ganache or local testnet by default
BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:8545")

class BlockchainService:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
    
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

blockchain_service = BlockchainService()

