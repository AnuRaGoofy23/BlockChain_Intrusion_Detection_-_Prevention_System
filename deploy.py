import os
import json
import sys
from web3 import Web3

def load_env(env_path=".env"):
    """Simple helper to load .env file variables into environment."""
    if not os.path.exists(env_path):
        print(f"Warning: {env_path} not found. Using system environment variables.")
        return
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            parts = line.split("=", 1)
            key = parts[0].strip()
            value = parts[1].strip()
            # Remove optional quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            os.environ[key] = value

def update_env(key, value, env_path=".env"):
    """Helper to update or append a key-value pair in .env file."""
    if not os.path.exists(env_path):
        # Create from .env.example if available, otherwise write directly
        if os.path.exists(".env.example"):
            with open(".env.example", "r") as src, open(".env", "w") as dst:
                dst.write(src.read())
        else:
            with open(".env", "w") as f:
                f.write(f"{key}={value}\n")
            return
            
    with open(env_path, "r") as f:
        lines = f.readlines()
        
    updated = False
    for i, line in enumerate(lines):
        clean_line = line.strip()
        if clean_line.startswith(f"{key}=") or (clean_line.startswith("#") and f"{key}=" in clean_line):
            lines[i] = f"{key}={value}\n"
            updated = True
            break
            
    if not updated:
        lines.append(f"\n{key}={value}\n")
        
    with open(env_path, "w") as f:
        f.writelines(lines)
    print(f"Updated {key} inside {env_path}")

def main():
    load_env()
    
    blockchain_url = os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:7545")
    wallet_address = os.getenv("WALLET_ADDRESS")
    private_key = os.getenv("PRIVATE_KEY")
    
    print(f"Connecting to blockchain at: {blockchain_url}")
    w3 = Web3(Web3.HTTPProvider(blockchain_url))
    
    if not w3.is_connected():
        print("Error: Could not connect to the Ethereum network.")
        sys.exit(1)
        
    print(f"Successfully connected to Ganache/Ethereum network. Chain ID: {w3.eth.chain_id}")
    
    # Validation checks
    if not wallet_address or not private_key:
        print("Error: WALLET_ADDRESS and PRIVATE_KEY must be configured in the .env file.")
        print("Please create a .env file containing:")
        print("  WALLET_ADDRESS=0x...")
        print("  PRIVATE_KEY=0x...")
        sys.exit(1)
        
    # Check JSON compilation output
    artifact_path = os.path.join("contracts", "ThreatLogger.json")
    if not os.path.exists(artifact_path):
        print(f"Error: Compiled contract artifact '{artifact_path}' not found.")
        print("Please run `python compile_contract.py` first to compile the contract.")
        sys.exit(1)
        
    with open(artifact_path, "r") as f:
        contract_data = json.load(f)
        
    abi = contract_data["abi"]
    bytecode = contract_data["bytecode"]
    
    # Format wallet address
    try:
        wallet_address = w3.to_checksum_address(wallet_address)
    except Exception as e:
        print(f"Invalid wallet address format: {e}")
        sys.exit(1)
        
    # Remove prefix if present in private key
    if private_key.startswith("0x"):
        private_key = private_key[2:]
        
    print(f"Preparing deployment from account: {wallet_address}")
    
    # Construct contract deployment transaction
    ThreatContract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Get nonce
    nonce = w3.eth.get_transaction_count(wallet_address)
    
    # Build transaction
    print("Building deployment transaction...")
    deploy_tx = ThreatContract.constructor().build_transaction({
        'from': wallet_address,
        'nonce': nonce,
        'gas': 3000000,
        'gasPrice': w3.eth.gas_price,
        'chainId': w3.eth.chain_id
    })
    
    # Sign transaction
    print("Signing transaction...")
    signed_tx = w3.eth.account.sign_transaction(deploy_tx, private_key=private_key)
    
    # Send transaction
    print("Sending transaction to blockchain...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Transaction Hash: {tx_hash.hex()}")
    
    # Wait for receipt
    print("Waiting for transaction receipt (mining)...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    
    print(f"Contract deployed successfully at address: {contract_address}")
    
    # Save contract address JSON
    address_output_path = os.path.join("contracts", "contract_address.json")
    with open(address_output_path, "w") as f:
        json.dump({"address": contract_address}, f, indent=4)
    print(f"Saved contract address to {address_output_path}")
    
    # Update local .env file
    update_env("THREAT_LOGGER_ADDRESS", contract_address)
    print("Deployment completed successfully!")

if __name__ == "__main__":
    main()
