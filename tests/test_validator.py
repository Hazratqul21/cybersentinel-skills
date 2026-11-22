import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersentinel.registry import Skill
from cybersentinel.validator import (
    validate_skill,
    validate_all,
    summarize,
    SEVERITY_ERROR,
)

VALID_BODY = textwrap.dedent(
    """
    ## Purpose
    Do a thing.
    ## Prerequisites
    Tools.
    ## Scope & Authorization
    Require written authorization and an in-scope target list.
    ## Methodology
    Phased approach.
    ## Execution Workflow
    1. Step one.
    ## Validation
    Confirm the finding.
    ## Expected Output
    Artifacts.
    ## False Positives
    Rule them out.
    ## Remediation
    Fix it.
    ## Reporting
    Template.
    ## References
    - https://example.com
    """
)


def write_skill(root: Path, category: str, name: str, frontmatter: str, body: str) -> Path:
    d = root / category / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return d


def good_frontmatter(name="sql-injection-testing", category="red-team", extra=""):
    return textwrap.dedent(
        f"""\
        name: {name}
        description: Identify and safely validate SQL injection in authorized web targets and produce remediation guidance.
        version: 1.0.0
        category: {category}
        authorization_required: true
        destructive: false{extra}"""
    )


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["CYBERSENTINEL_ROOT"] = str(self.root)
        # Minimal markers so repo_root heuristics don't wander off.
        (self.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        (self.root / "red-team").mkdir(exist_ok=True)

    def tearDown(self):
        os.environ.pop("CYBERSENTINEL_ROOT", None)
        self.tmp.cleanup()

    def _errors(self, issues):
        return [i for i in issues if i.severity == SEVERITY_ERROR]

    def test_valid_skill_passes(self):
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), VALID_BODY)
        issues = validate_skill(Skill.load(d))
        self.assertEqual(self._errors(issues), [], msg=str([str(i) for i in issues]))

    def test_missing_description(self):
        fm = "name: no-desc-skill\nversion: 1.0.0\ncategory: blue-team"
        d = write_skill(self.root, "blue-team/soc-analysis", "no-desc-skill", fm, VALID_BODY)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("description" in i.message for i in self._errors(issues)))

    def test_name_mismatch(self):
        fm = good_frontmatter(name="different-name")
        d = write_skill(self.root, "red-team/web-security", "actual-dir-name", fm, VALID_BODY)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("does not match directory" in i.message for i in issues))

    def test_bad_name_regex(self):
        fm = good_frontmatter(name="Bad_Name")
        d = write_skill(self.root, "red-team/web-security", "Bad_Name", fm, VALID_BODY)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("must match" in i.message for i in self._errors(issues)))

    def test_missing_required_section(self):
        body = VALID_BODY.replace("## Remediation\nFix it.\n", "")
        self.assertNotIn("## Remediation", body)  # guard: the removal actually happened
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), body)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("Remediation" in i.message for i in self._errors(issues)))

    def test_offensive_requires_authorization(self):
        fm = textwrap.dedent(
            """\
            name: dangerous-skill
            description: An offensive skill that forgot to declare authorization requirements here.
            version: 1.0.0
            category: red-team
            authorization_required: false"""
        )
        d = write_skill(self.root, "red-team/web-security", "dangerous-skill", fm, VALID_BODY)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(
            any("authorization_required: true" in i.message for i in self._errors(issues))
        )

    def test_dangerous_script_flagged(self):
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), VALID_BODY)
        scripts = d / "scripts"
        scripts.mkdir()
        (scripts / "danger.sh").write_text("#!/bin/bash\nrm -rf /\n", encoding="utf-8")
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("dangerous pattern" in i.message for i in self._errors(issues)))

    def test_dangerous_script_allowlisted(self):
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), VALID_BODY)
        scripts = d / "scripts"
        scripts.mkdir()
        (scripts / "ok.sh").write_text(
            "#!/bin/bash\n# cybersentinel: allow-dangerous: lab teardown only\nshutdown now\n",
            encoding="utf-8",
        )
        issues = validate_skill(Skill.load(d))
        self.assertFalse(any("dangerous pattern" in i.message for i in self._errors(issues)))

    def test_broken_relative_link(self):
        body = VALID_BODY + "\nSee [methodology](references/missing.md).\n"
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), body)
        issues = validate_skill(Skill.load(d))
        self.assertTrue(any("broken relative link" in i.message for i in self._errors(issues)))

    def test_valid_relative_link_ok(self):
        d = write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                        good_frontmatter(), VALID_BODY + "\n[m](references/methodology.md)\n")
        (d / "references").mkdir()
        (d / "references" / "methodology.md").write_text("# m", encoding="utf-8")
        issues = validate_skill(Skill.load(d))
        self.assertFalse(any("broken relative link" in i.message for i in issues))

    def test_duplicate_names_detected(self):
        write_skill(self.root, "red-team/web-security", "dup-skill",
                    good_frontmatter(name="dup-skill"), VALID_BODY)
        write_skill(self.root, "blue-team/soc-analysis", "dup-skill",
                    good_frontmatter(name="dup-skill", category="blue-team"), VALID_BODY)
        issues = validate_all(self.root)
        self.assertTrue(any("duplicate skill name" in i.message for i in issues))

    def test_summarize_counts(self):
        write_skill(self.root, "red-team/web-security", "sql-injection-testing",
                    good_frontmatter(), VALID_BODY)
        counts = summarize(validate_all(self.root))
        self.assertEqual(counts["errors"], 0)


if __name__ == "__main__":
    unittest.main()
