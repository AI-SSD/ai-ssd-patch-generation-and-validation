import unittest

from cve_aggregator.models import CVEEntry, CVEMetadata, Dataset, ExploitInfo
from cve_aggregator.modules.syntax_validator import SyntaxValidator


class SyntaxValidatorAutoCommentTests(unittest.TestCase):
    def setUp(self):
        self.sv = SyntaxValidator({})

    def test_c_top_and_bottom_prose_are_commented_and_validated(self):
        content = """// source: https://www.securityfocus.com/bid/55462/info

GNU glibc is prone to a remote integer-overflow vulnerability which leads to buffer overflow vulnerability.

#include <stdio.h>
int main(void) {
  return 0;
}

Successful exploits may allow an attacker to execute arbitrary code in the context of a user running an application that uses the affected library.
"""
        fixed, changed = self.sv._auto_comment_uncommented_prose_for_language(content, "c")
        self.assertGreaterEqual(changed, 2)
        self.assertIn("// GNU glibc is prone", fixed)
        self.assertIn("// Successful exploits may allow", fixed)

        result = self.sv._validate(content, "c", {})
        self.assertTrue(result.is_valid)
        self.assertFalse(result.needs_manual_review)

    def test_python_top_and_bottom_prose_are_commented_and_validated(self):
        content = """This exploit is prone to vulnerability and allows attacker execution in application context.

import sys
print(\"ok\")

Failed exploit attempts may crash the application, denying service to legitimate users in context of a user running it.
"""
        fixed, changed = self.sv._auto_comment_uncommented_prose_for_language(content, "python")
        self.assertGreaterEqual(changed, 2)
        self.assertIn("# This exploit is prone", fixed)
        self.assertIn("# Failed exploit attempts may crash", fixed)

        result = self.sv._validate(content, "python", {})
        self.assertTrue(result.is_valid)
        self.assertFalse(result.needs_manual_review)

    def test_does_not_comment_regular_code_lines(self):
        content = """import os
value = 42
print(value)
"""
        fixed, changed = self.sv._auto_comment_uncommented_prose_for_language(content, "python")
        self.assertEqual(changed, 0)
        self.assertEqual(fixed, content)

    def test_run_persists_auto_commented_content(self):
        content = """// source: https://www.securityfocus.com/bid/55462/info

GNU glibc is prone to a remote integer-overflow vulnerability which leads to buffer overflow vulnerability.

#include <stdio.h>
int main(void) {
  return 0;
}
"""

        entry = CVEEntry(
            metadata=CVEMetadata(cve_id="CVE-TEST-0001"),
            exploits=[ExploitInfo(language="c", source_code_content=content, verified=True)],
        )
        dataset = Dataset(cves={"CVE-TEST-0001": entry})

        context = {"dataset": dataset}
        out = self.sv.run(context)

        updated = out["dataset"].cves["CVE-TEST-0001"].exploits[0].source_code_content
        self.assertIn("// GNU glibc is prone", updated)

    def test_success_rate_simple_and_intricate_cases(self):
        cases = [
            {
                "name": "c_simple_top",
                "language": "c",
                "content": """GNU glibc is prone to vulnerability and allows attacker code execution in application context.
#include <stdio.h>
int main(void){return 0;}
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": True,
            },
            {
                "name": "c_intricate_top_bottom",
                "language": "c",
                "content": """// source: ref
GNU glibc is prone to vulnerability and allows attacker code execution in application context.
#include <stdio.h>
int main(void){return 0;}
Successful exploits may allow an attacker to execute arbitrary code in context of a user running an application.
""",
                "expected_changed_min": 2,
                "expect_valid_after_validate": True,
            },
            {
                "name": "python_simple_top",
                "language": "python",
                "content": """This exploit is prone to vulnerability and allows attacker execution in application context.
import sys
print(\"ok\")
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": True,
            },
            {
                "name": "python_intricate_bottom",
                "language": "python",
                "content": """import sys
print(\"ok\")
Failed exploit attempts may crash the application denying service to legitimate users in context of a user.
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": True,
            },
            {
                "name": "shell_simple_top",
                "language": "shell",
                "content": """This exploit is prone to vulnerability and allows attacker execution in application context.
echo ok
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": False,
            },
            {
                "name": "ruby_intricate_top_bottom",
                "language": "ruby",
                "content": """This exploit is prone to vulnerability and allows attacker execution in application context.
puts 'ok'
Successful exploits may allow an attacker to execute arbitrary code in context of a user running an application.
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": False,
            },
            {
                "name": "perl_intricate_top_bottom",
                "language": "perl",
                "content": """This exploit is prone to vulnerability and allows attacker execution in application context.
print \"ok\\n\";
Failed exploit attempts may crash the application denying service to legitimate users in context of a user.
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": False,
            },
            {
                "name": "php_intricate_top_bottom",
                "language": "php",
                "content": """This exploit is prone to vulnerability and allows attacker execution in application context.
<?php
echo \"ok\";
?>
Successful exploits may allow an attacker to execute arbitrary code in context of a user running an application.
""",
                "expected_changed_min": 1,
                "expect_valid_after_validate": False,
            },
        ]

        successes = 0
        strict_cases = 0

        for case in cases:
            fixed, changed = self.sv._auto_comment_uncommented_prose_for_language(
                case["content"], case["language"]
            )
            detection_ok = changed >= case["expected_changed_min"]
            if detection_ok:
                successes += 1

            if case["expect_valid_after_validate"]:
                strict_cases += 1
                res = self.sv._validate(case["content"], case["language"], {})
                if res.is_valid:
                    successes += 1

        total_checks = len(cases) + strict_cases
        success_rate = successes / total_checks

        # We expect very high reliability on this curated test suite.
        self.assertGreaterEqual(success_rate, 0.90)


if __name__ == "__main__":
    unittest.main()
