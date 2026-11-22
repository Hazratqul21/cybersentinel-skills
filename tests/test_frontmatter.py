import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersentinel.frontmatter import parse_frontmatter, split_frontmatter, FrontmatterError


class TestFrontmatter(unittest.TestCase):
    def test_basic_scalars(self):
        doc = "---\nname: foo-bar\ndescription: A test skill.\nversion: 1.0.0\n---\n# Body\n"
        fm, body = parse_frontmatter(doc)
        self.assertEqual(fm["name"], "foo-bar")
        self.assertEqual(fm["description"], "A test skill.")
        self.assertEqual(fm["version"], "1.0.0")
        self.assertIn("# Body", body)

    def test_inline_list(self):
        doc = "---\nname: x\ntags: [web-security, injection, owasp-top-10]\n---\nbody"
        fm, _ = parse_frontmatter(doc)
        self.assertEqual(fm["tags"], ["web-security", "injection", "owasp-top-10"])

    def test_block_list(self):
        doc = (
            "---\n"
            "name: x\n"
            "references:\n"
            "  - https://a.example\n"
            "  - https://b.example\n"
            "---\n"
            "body"
        )
        fm, _ = parse_frontmatter(doc)
        self.assertEqual(fm["references"], ["https://a.example", "https://b.example"])

    def test_booleans(self):
        doc = "---\nname: x\nauthorization_required: true\ndestructive: false\n---\nb"
        fm, _ = parse_frontmatter(doc)
        self.assertIs(fm["authorization_required"], True)
        self.assertIs(fm["destructive"], False)

    def test_quoted_string_with_colon(self):
        doc = '---\nname: x\ndescription: "A: colon, and comma"\n---\nb'
        fm, _ = parse_frontmatter(doc)
        self.assertEqual(fm["description"], "A: colon, and comma")

    def test_missing_fence_raises(self):
        with self.assertRaises(FrontmatterError):
            parse_frontmatter("no frontmatter here")

    def test_unclosed_fence_raises(self):
        with self.assertRaises(FrontmatterError):
            split_frontmatter("---\nname: x\nbody without close")


if __name__ == "__main__":
    unittest.main()
