"""End-to-end tests for the `cybersentinel` CLI entrypoint (main()).

These drive the argparse dispatch and assert exit codes and output so the
command contract (list/search/info/validate/install/--version) stays stable.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersentinel.cli import main


def run(argv):
    """Invoke main(argv), capturing (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestNoArgsAndVersion(unittest.TestCase):
    def test_no_args_prints_help(self):
        code, out, _ = run([])
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())

    def test_version_exits_zero(self):
        # argparse's version action raises SystemExit(0).
        with self.assertRaises(SystemExit) as cm:
            run(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestList(unittest.TestCase):
    def test_list_returns_zero_and_counts(self):
        code, out, _ = run(["list"])
        self.assertEqual(code, 0)
        self.assertIn("skill(s).", out)

    def test_list_json_is_valid(self):
        code, out, _ = run(["list", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertTrue(all("id" in d and "name" in d for d in data))

    def test_list_category_filters(self):
        code, out, _ = run(["list", "--category", "dfir"])
        self.assertEqual(code, 0)
        # every printed skill line should be a dfir skill
        ids = [ln.split()[0] for ln in out.splitlines()
               if ln and not ln.startswith(("\n",)) and "/" in ln.split(" ")[0]]
        self.assertTrue(ids)
        self.assertTrue(all(i.startswith("dfir/") for i in ids))


class TestSearch(unittest.TestCase):
    def test_search_normalized_match(self):
        code, out, _ = run(["search", "sqli"])
        self.assertEqual(code, 0)
        self.assertIn("sql-injection-testing", out)

    def test_search_no_match_is_zero(self):
        code, out, _ = run(["search", "zzzznotareal termzzzz"])
        self.assertEqual(code, 0)
        self.assertIn("0 match(es)", out)


class TestInfo(unittest.TestCase):
    def test_info_found(self):
        code, out, _ = run(["info", "threat-actor-profiling"])
        self.assertEqual(code, 0)
        self.assertIn("threat-actor-profiling", out)
        self.assertIn("ATT&CK", out)

    def test_info_not_found_exit_2(self):
        code, _, err = run(["info", "definitely-not-a-skill"])
        self.assertEqual(code, 2)
        self.assertIn("not found", err.lower())


class TestValidate(unittest.TestCase):
    def test_validate_repo_clean(self):
        code, out, _ = run(["validate"])
        self.assertEqual(code, 0)
        self.assertIn("0 error(s)", out)

    def test_validate_strict_repo_clean(self):
        # The shipped repo has zero warnings, so --strict must also pass.
        code, out, _ = run(["validate", "--strict"])
        self.assertEqual(code, 0)


class TestInstallCommand(unittest.TestCase):
    def test_install_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run([
                "install", "--path", tmp,
                "--skill", "sql-injection-testing", "--dry-run",
            ])
            self.assertEqual(code, 0)
            self.assertIn("[dry-run]", out)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_install_real_copies_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = run([
                "install", "--path", tmp, "--skill", "sql-injection-testing",
            ])
            self.assertEqual(code, 0)
            self.assertTrue((Path(tmp) / "sql-injection-testing" / "SKILL.md").exists())

    def test_install_unknown_skill_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run([
                "install", "--path", tmp, "--skill", "no-such-skill",
            ])
            self.assertEqual(code, 2)
            self.assertIn("not found", err.lower())


if __name__ == "__main__":
    unittest.main()
