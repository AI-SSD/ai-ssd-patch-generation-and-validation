import re

with open('orchestrator.py', 'r') as f:
    content = f.read()

# 1. Add self.poc_analyzer
content = content.replace(
    'self._manifest = ImageManifest(self._p1["image_manifest_path"], self.logger)',
    'self._manifest = ImageManifest(self._p1["image_manifest_path"], self.logger)\n        self.poc_analyzer = PoCAnalyzer(self.logger)'
)

# 2. Pass poc_metadata in _process_vulnerability_phase0
old_proc = '''            # Detect PoC language from CSV or file extension
            poc_language = vuln.poc_language or self.poc_mgr.detect_language(poc_path)
            self.logger.info(f"  PoC language: {poc_language} ({poc_path.name})")
            
            base_tag = vuln.base_image_tag
            success, build_logs = self._cve_builder.build_cve_image(
                vuln, base_tag, poc_path, poc_language
            )'''

new_proc = '''            # Detect PoC language from CSV or file extension
            poc_language = vuln.poc_language or self.poc_mgr.detect_language(poc_path)
            self.logger.info(f"  PoC language: {poc_language} ({poc_path.name})")
            
            # Extract PoC metadata via LLM
            poc_metadata = self.poc_analyzer.analyze_poc(poc_path)
            
            base_tag = vuln.base_image_tag
            success, build_logs = self._cve_builder.build_cve_image(
                vuln, base_tag, poc_path, poc_language, poc_metadata
            )'''
content = content.replace(old_proc, new_proc)

# 3. Update build_cve_image signature
content = content.replace(
    'def build_cve_image(self, vuln: VulnerabilityInfo, base_image_tag: str,\n                        poc_path: Path, poc_language: str = None) -> Tuple[bool, Optional[str]]:',
    'def build_cve_image(self, vuln: VulnerabilityInfo, base_image_tag: str,\n                        poc_path: Path, poc_language: str = None, poc_metadata: dict = None) -> Tuple[bool, Optional[str]]:'
)

# Pass poc_metadata to _generate_dockerfile
content = content.replace(
    '''            # Generate language-aware Dockerfile
            dockerfile_content = self._generate_dockerfile(
                vuln, base_image_tag, poc_filename, poc_language,
                alt_poc_filenames=alt_poc_filenames,
            )''',
    '''            # Generate language-aware Dockerfile
            dockerfile_content = self._generate_dockerfile(
                vuln, base_image_tag, poc_filename, poc_language,
                alt_poc_filenames=alt_poc_filenames,
                poc_metadata=poc_metadata
            )'''
)

# 4. Update _generate_dockerfile signature
content = content.replace(
    'def _generate_dockerfile(self, vuln: VulnerabilityInfo, base_image_tag: str,\n                              poc_filename: str, poc_language: str,\n                              alt_poc_filenames: List[str] = None) -> str:',
    'def _generate_dockerfile(self, vuln: VulnerabilityInfo, base_image_tag: str,\n                              poc_filename: str, poc_language: str,\n                              alt_poc_filenames: List[str] = None, poc_metadata: dict = None) -> str:'
)

# Inject wrapper.sh generation
wrapper_injection = '''
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
content = content.replace(
    '        self.logger.info(f"Generated {lang} Dockerfile for {vuln.cve}")\n        return header + body',
    wrapper_injection
)

# 5. Update _interpret_exit_code
exit_code_logic = '''        logs_lower = logs.lower()
        
        if exit_code == 42:
            self.logger.info(f"{vuln.cve}: PoC wrapper exited with 42 - vulnerability confirmed")
            return True
        if exit_code == 43:
            self.logger.warning(f"{vuln.cve}: PoC wrapper exited with 43 - vulnerability NOT reproduced")
            return False
'''
content = content.replace(
    '        logs_lower = logs.lower()',
    exit_code_logic,
    1
)

with open('orchestrator.py', 'w') as f:
    f.write(content)
