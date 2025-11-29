## General Methodology for Patch Generation and Validation (T4)

The overall methodology is a cyclical, multi-stage process that systematically leverages GenAI, dynamic testing and static analysis to automate secure patching.

---

### **Phase 1: Vulnerability Identification and Environment Setup**

This phase mirrors the initial steps of the project's general methodology to establish a foundational test environment.

1. **Select Target Vulnerability (CVE):** Identify a specific vulnerability (e.g., a **CVE**) in a large open-source project, a C/C++ project, to focus on.
2. **Establish Virtual Environments:** Create two distinct, reproducible virtual environments :
   * **Test Environment:** Based on the **vulnerable** version of the target software.
   * **Control Environment:** Based on the **non-vulnerable** (patched/fixed) version of the target software, used as a secure reference point.
3. **Vulnerability Replication:** Create or obtain an ****Exploit/Proof-of-Concept (PoC)** tailored to the vulnerability. Run the PoC in the** **Test Environment** to confirm the desired failure/exploit behavior.

---

### **Phase 2: Automated Patch Generation (GenAI Focus)**

This is where the Large Language Model (LLM) is applied to the vulnerable code.

1. **Code Analysis and Prompting:** Feed the LLM with the vulnerable function, the full s<urrounding source file context (if available) and the PoC/Exploit code for maximal context.
2. **Patch Generation:** Prompt the LLM to generate a **complete, corrected code patch** for the vulnerable function, ensuring the fix adheres to secure coding practices and principles of software development.
3. **Extract Patch Artifacts:** Separate the LLM's raw output into:
   * The **Patched Function** .
   * Any **New Helper Functions** created by the LLM for the fix.

---

### **Phase 3: Multi-Layered Validation (The Core Contribution)**

This phase is critical for validating the quality and security of the AI-generated patch.

1. **Dynamic Functional Validation (Mitigation Check):**
   * Apply the generated patch to the code in the **Test Environment** .
   * **Re-run the original PoC/Exploit:** The patch is functionally valid if the exploit now **fails** and the program exhibits safe, non-vulnerable behavior (e.g., handles the error gracefully, crashes safely).
2. **Static Security Validation (New Vulnerability Check - SAST):**
   * Use one or more ****Static Application Security Testing (SAST)** tools (e.g., SonarQube, Snyk Code, Coverity) to analyze the** **patched code** .
   * Scan the patched function and any new helper functions to detect if the GenAI introduced ****new** or** **secondary vulnerabilities** (e.g., a new buffer overflow, incorrect access control or a different type of memory corruption).
3. **Static Quality Validation (Code Quality Check):**
   * Use static analysis to assess code quality metrics (e.g., maintainability, cyclomatic complexity, code smells) to ensure the patch is readable and maintainable.

---

### **Phase 4: Refinement, Analysis and Documentation**

1. **Refinement Loop (If Validation Fails):** If the patch fails ***either* the dynamic security check (PoC still works)** or the static security check (SAST detects new issues), generate new prompts for the LLM that include the validation failure feedback and repeat Phase 2.
2. **Results Documentation:** Document the final results, including:
   * The original CVE and vulnerable code.
   * The GenAI-generated patch.
   * The patch explanation (the "diff" and security rationale).
   * Validation results (PoC failure, SAST scan outcome).
   * Analysis of the GenAI model's performance (speed, success rate and vulnerability type identification) based on the benchmarking script you created.

---

# Thesis Methodology Diagram

---
