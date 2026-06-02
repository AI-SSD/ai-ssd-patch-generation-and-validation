import re

with open('orchestrator.py', 'r') as f:
    content = f.read()

# Replace the old wrapper injection logic with the new dynamic one
old_wrapper_injection = '''
        self.logger.info(f"Generated {lang} Dockerfile for {vuln.cve}")
        
        # Inject execution wrapper based on metadata
        poc_type = poc_metadata.get("type", "OTHER") if poc_metadata else "OTHER"
        
        wrapper_sh = ["#!/bin/bash", f"echo 'Executing wrapper for type: {poc_type}'"]
        
        # Determine the base execution command from the original CMD
        import re
        cmd_match = re.search(r'CMD \\["(.*?)\\"(?:, \\"(.*?)\\")?\\]', body)
        if cmd_match:
            if cmd_match.group(2):
                base_cmd = f"{cmd_match.group(1)} {cmd_match.group(2)}"
            else:
                base_cmd = cmd_match.group(1)
            # Remove original CMD
            body = re.sub(r'CMD \\[.*?\\]\\n?', '', body)
        else:
            base_cmd = "./exploit"
            
        if poc_type == "LPE":
            wrapper_sh.append("echo -e 'id\\nexit\\n' > /tmp/cmds.txt")
            wrapper_sh.append(f"{base_cmd} < /tmp/cmds.txt > /tmp/out 2>&1")
            wrapper_sh.append("if grep -q 'uid=0' /tmp/out || grep -q 'root' /tmp/out; then exit 42; else cat /tmp/out; exit 43; fi")
        elif poc_type == "DOS":
            wrapper_sh.append(f"{base_cmd}")
            wrapper_sh.append("exit_code=$?")
            wrapper_sh.append("if [ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || [ $exit_code -eq 137 ]; then exit 42; else exit 43; fi")
        elif poc_type == "INFO_LEAK":
            pattern = poc_metadata.get("info_pattern") or "root:.*:0:0:"
            wrapper_sh.append(f"{base_cmd} > /tmp/out 2>&1")
            wrapper_sh.append(f"if grep -qE '{pattern}' /tmp/out; then exit 42; else cat /tmp/out; exit 43; fi")
        elif poc_type == "SUID_DROPPER":
            suid_path = poc_metadata.get("suid_path") or "/tmp/kidd0"
            wrapper_sh.append(f"{base_cmd}")
            wrapper_sh.append(f"if [ -u '{suid_path}' ]; then exit 42; else exit 43; fi")
        elif poc_type == "METASPLOIT":
            wrapper_sh.append(f"{base_cmd}")
            wrapper_sh.append("if [ $? -eq 0 ]; then exit 42; else exit 43; fi")
        else:
            wrapper_sh.append(f"{base_cmd}")
            wrapper_sh.append("exit_code=$?")
            wrapper_sh.append("if [ $exit_code -eq 0 ]; then exit 42; else exit 43; fi")
            
        wrapper_cmds = "\\n".join(wrapper_sh).replace('"', '\\\\"')
        body += f'\\nRUN echo -e "{wrapper_cmds}" > /poc/wrapper.sh && chmod +x /poc/wrapper.sh\\n'
        body += 'CMD ["/bin/bash", "/poc/wrapper.sh"]\\n'
        
        return header + body
'''

new_wrapper_injection = '''
        self.logger.info(f"Generated {lang} Dockerfile for {vuln.cve}")
        
        # Determine the base execution command from the original CMD to pass context if needed
        import re
        cmd_match = re.search(r'CMD \\["(.*?)\\"(?:, \\"(.*?)\\")?\\]', body)
        base_cmd = "./exploit"
        if cmd_match:
            if cmd_match.group(2):
                base_cmd = f"{cmd_match.group(1)} {cmd_match.group(2)}"
            else:
                base_cmd = cmd_match.group(1)
            # Remove original CMD
            body = re.sub(r'CMD \\[.*?\\]\\n?', '', body)
            
        # Get dynamic wrapper parameters from LLM analysis
        poc_category = poc_metadata.get("poc_category", "OTHER") if poc_metadata else "OTHER"
        setup_cmd = poc_metadata.get("setup_command", "") if poc_metadata else ""
        exec_wrap = poc_metadata.get("execution_wrapper", base_cmd) if poc_metadata else base_cmd
        verify_cmd = poc_metadata.get("verification_command", "exit_code=$?; [ $exit_code -eq 0 ]") if poc_metadata else "exit_code=$?; [ $exit_code -eq 0 ]"
        
        # Build the dynamic wrapper script
        wrapper_sh = [
            "#!/bin/bash",
            f"echo '--- Executing dynamic wrapper for category: {poc_category} ---'",
            "# 1. Setup Phase",
            setup_cmd,
            "",
            "# 2. Execution Phase",
            "echo '--- Running exploit ---'",
            exec_wrap,
            "exit_code=$?",
            "echo '--- Exploit finished ---'",
            "",
            "# 3. Verification Phase",
            f"if eval \\"{verify_cmd}\\"; then",
            "    echo '--- VERIFICATION SUCCESS: Vulnerability Confirmed ---'",
            "    exit 42",
            "else",
            "    echo '--- VERIFICATION FAILED: Not Reproduced ---'",
            "    exit 43",
            "fi"
        ]
        
        wrapper_cmds = "\\n".join(wrapper_sh).replace('"', '\\\\"')
        body += f'\\nRUN echo -e "{wrapper_cmds}" > /poc/wrapper.sh && chmod +x /poc/wrapper.sh\\n'
        body += 'CMD ["/bin/bash", "/poc/wrapper.sh"]\\n'
        
        return header + body
'''

content = content.replace(old_wrapper_injection, new_wrapper_injection)

with open('orchestrator.py', 'w') as f:
    f.write(content)
