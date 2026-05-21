import re

class ContractAnalyzer:
    def analyze_solidity(self, code: str):
        findings = []
        lines = code.split('\n')
        
        current_function = None
        has_call = False
        call_line = 0
        
        # 1. Reentrancy Scan
        for idx, line in enumerate(lines):
            line_num = idx + 1
            # Match function declarations
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                current_function = func_match.group(1)
                has_call = False
                call_line = 0
                
            # Scan for external calls inside functions
            if current_function and ('.call{' in line or '.transfer(' in line or '.send(' in line):
                has_call = True
                call_line = line_num
                
            # State update after external call
            if current_function and has_call and '=' in line and not any(k in line for k in ['==', 'require', 'assert', 'revert']):
                findings.append({
                    "type": "Reentrancy Vulnerability",
                    "severity": "Critical",
                    "line": line_num,
                    "description": f"Potential reentrancy vulnerability in function '{current_function}'. State change occurs on line {line_num} after external transfer/call on line {call_line}. Ensure checks-effects-interactions pattern is followed.",
                    "code_snippet": line.strip()
                })
                has_call = False # avoid duplicate flags for the same function

        # 2. Unprotected Selfdestruct Scan
        current_function_decl = ""
        is_public_external = False
        has_access_control = False
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            func_match = re.search(r'function\s+(\w+)\s*\([^)]*\)\s*([^{]+)', line)
            if func_match:
                current_function_decl = func_match.group(1)
                attrs = func_match.group(2)
                is_public_external = 'public' in attrs or 'external' in attrs
                has_access_control = any(ac in attrs for ac in ['onlyOwner', 'onlyAdmin', 'require', 'modifier'])
                
            if 'selfdestruct(' in line or 'suicide(' in line:
                if is_public_external and not has_access_control:
                    findings.append({
                        "type": "Unprotected Selfdestruct",
                        "severity": "Critical",
                        "line": line_num,
                        "description": f"Function '{current_function_decl}' exposes selfdestruct/suicide to public callers without any ownership authorization modifier.",
                        "code_snippet": line.strip()
                    })

        # 3. Missing Access Control Scan
        critical_words = ['withdraw', 'transferownership', 'setowner', 'pause', 'unpause', 'mint', 'burn', 'setadmin']
        for idx, line in enumerate(lines):
            line_num = idx + 1
            func_match = re.search(r'function\s+(\w+)\s*\([^)]*\)\s*([^{]+)', line)
            if func_match:
                func_name = func_match.group(1)
                attrs = func_match.group(2)
                if any(word in func_name.lower() for word in critical_words):
                    is_public = 'public' in attrs or 'external' in attrs
                    has_check = any(check in attrs for check in ['onlyOwner', 'onlyAdmin', 'onlyRole'])
                    if is_public and not has_check:
                        # Scan function body for require checks
                        body_has_require = False
                        for offset in range(1, 6):
                            if idx + offset < len(lines):
                                body_line = lines[idx + offset]
                                if 'require(' in body_line or 'revert(' in body_line:
                                    body_has_require = True
                        if not body_has_require:
                            findings.append({
                                "type": "Missing Access Control",
                                "severity": "High Risk",
                                "line": line_num,
                                "description": f"Function '{func_name}' executes a critical state adjustment but lacks 'onlyOwner', 'onlyAdmin', or dynamic requirement checks.",
                                "code_snippet": line.strip()
                            })

        # 4. Unsafe Infinite Approvals Scan
        for idx, line in enumerate(lines):
            line_num = idx + 1
            if 'approve(' in line and ('1157920892' in line or 'type(uint256).max' in line or '0xffffffffffffff' in line or 'uint256(-1)' in line):
                findings.append({
                    "type": "Unsafe Approval Pattern",
                    "severity": "Medium Risk",
                    "line": line_num,
                    "description": "Standard infinite token approval detected. Consider utilizing safeApprove/increaseAllowance or checking exact required amounts.",
                    "code_snippet": line.strip()
                })

        return findings

contract_analyzer = ContractAnalyzer()
