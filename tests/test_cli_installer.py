import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersentinel.cli import _norm
from cybersentinel.installer import install_skill, resolve_agent_dir, AGENT_PATHS


class TestSearchNorm(unittest.TestCase):
    def test_norm_strips_nonalnum(self):
        self.assertEqual(_norm("SQL injection!"), "sqlinjection")
        # 'sqli' is a substring of normalized 'sql injection testing'
        self.assertIn("sqli", _norm("SQL injection testing"))


class TestInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # a fake skill directory
        self.skill = self.root / "src-skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("---\nname: x\n---\nbody", encoding="utf-8")
        self.dest = self.root / "dest"

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_then_skip_then_force(self):
        r1 = install_skill(self.skill, self.dest)
        self.assertEqual(r1.status, "installed")
        self.assertTrue((self.dest / "src-skill" / "SKILL.md").exists())

        r2 = install_skill(self.skill, self.dest)
        self.assertEqual(r2.status, "skipped-exists")

        r3 = install_skill(self.skill, self.dest, force=True)
        self.assertEqual(r3.status, "overwritten")

    def test_dry_run_writes_nothing(self):
        r = install_skill(self.skill, self.dest, dry_run=True)
        self.assertEqual(r.status, "installed")
        self.assertFalse(self.dest.exists())

    def test_resolve_known_agents(self):
        for agent in AGENT_PATHS:
            p = resolve_agent_dir(agent)
            self.assertTrue(p.is_absolute())

    def test_resolve_unknown_agent_raises(self):
        with self.assertRaises(ValueError):
            resolve_agent_dir("no-such-agent")

    def test_custom_path_overrides(self):
        p = resolve_agent_dir("claude-code", custom_path=str(self.root / "custom"))
        self.assertEqual(p, (self.root / "custom").resolve())


if __name__ == "__main__":
    unittest.main()
