import os
import json
import sys

def main():
    print("Installing/Checking py-solc-x dependency...")
    try:
        import solcx
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "py-solc-x"])
        import solcx

    # Ensure solc is installed
    solc_version = "0.8.20"
    installed_versions = solcx.get_installed_solc_versions()
    if solc_version not in [str(v) for v in installed_versions]:
        print(f"Downloading solc version {solc_version}...")
        solcx.install_solc(solc_version)
    
    solcx.set_solc_version(solc_version)
    
    contract_path = os.path.join("contracts", "ThreatLogger.sol")
    print(f"Compiling {contract_path}...")
    
    try:
        compiled_sol = solcx.compile_files(
            [contract_path],
            output_values=["abi", "bin"],
            solc_version=solc_version
        )
        
        # Get the compiled contract contract info
        contract_key = f"{contract_path}:ThreatLogger"
        if contract_key not in compiled_sol:
            # Try alternate key format
            contract_key = next(k for k in compiled_sol.keys() if "ThreatLogger" in k)
            
        contract_data = compiled_sol[contract_key]
        
        output_data = {
            "abi": contract_data["abi"],
            "bytecode": contract_data["bin"]
        }
        
        output_path = os.path.join("contracts", "ThreatLogger.json")
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=4)
            
        print(f"Successfully compiled and saved to {output_path}!")
        return True
    except Exception as e:
        print(f"Compilation failed: {e}")
        return False

if __name__ == "__main__":
    main()
