#!/usr/bin/env python3
"""Tests for setup_auto_mode.py.

Every test installs into a throwaway directory, so nothing here touches the
real ~/.gemini. Run with:

    python3 -m unittest discover -v
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import setup_auto_mode as sam


class InstallerTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="agy-auto-mode-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.paths = sam.Paths(gemini_dir=os.path.join(self.root, ".gemini"))

    # -- helpers ----------------------------------------------------------

    def write(self, path, content):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)

    def read(self, path):
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def apply(self, planner):
        actions, _ = planner(self.paths)
        with contextlib.redirect_stdout(io.StringIO()):
            sam.apply_actions(actions)

    def install(self):
        self.apply(sam.plan_install)

    def revert(self):
        self.apply(sam.plan_revert)

    def files(self):
        found = []
        for directory, _, names in os.walk(self.root):
            for name in names:
                found.append(os.path.relpath(os.path.join(directory, name), self.root))
        return sorted(found)

    def settings(self):
        return json.loads(self.read(self.paths.settings))


class TestFreshInstall(InstallerTestCase):
    def test_install_creates_everything(self):
        self.install()
        self.assertEqual(self.read(self.paths.agent), sam.AGENT_MD)
        self.assertIn(sam.MARKER_BEGIN, self.read(self.paths.rule))
        self.assertEqual(self.settings(), sam.AUTO_MODE_SETTINGS)

    def test_revert_leaves_nothing_behind(self):
        self.install()
        self.revert()
        self.assertEqual(self.files(), [])

    def test_install_is_idempotent(self):
        self.install()
        first = {path: self.read(os.path.join(self.root, path)) for path in self.files()}
        actions, notes = sam.plan_install(self.paths)
        self.assertEqual(actions, [])
        self.assertEqual(len(notes), 3)
        self.assertEqual({path: self.read(os.path.join(self.root, path)) for path in self.files()}, first)


class TestExistingConfig(InstallerTestCase):
    """The user's own files must come back byte for byte."""

    RULE = "# My notes\n\nUse tabs.\n"
    SETTINGS = '{\n  "theme": "dark",\n  "toolPermission": "ask"\n}\n'

    def setUp(self):
        super(TestExistingConfig, self).setUp()
        self.write(self.paths.rule, self.RULE)
        self.write(self.paths.settings, self.SETTINGS)

    def test_install_preserves_user_content(self):
        self.install()
        rule = self.read(self.paths.rule)
        self.assertTrue(rule.startswith(self.RULE))
        self.assertIn(sam.MARKER_BEGIN, rule)
        self.assertEqual(self.settings()["theme"], "dark")
        self.assertEqual(self.settings()["toolPermission"], "always-proceed")

    def test_round_trip_restores_both_files(self):
        self.install()
        self.revert()
        self.assertEqual(self.read(self.paths.rule), self.RULE)
        self.assertEqual(self.settings(), {"theme": "dark", "toolPermission": "ask"})

    def test_rule_is_separated_by_exactly_one_blank_line(self):
        self.install()
        self.assertIn("Use tabs.\n\n" + sam.MARKER_BEGIN, self.read(self.paths.rule))

    def test_backups_are_removed_on_revert(self):
        self.install()
        self.assertTrue(os.path.exists(self.paths.backup))
        self.assertTrue(os.path.exists(self.paths.rule_backup))
        self.revert()
        self.assertFalse(os.path.exists(self.paths.backup))
        self.assertFalse(os.path.exists(self.paths.rule_backup))

    def test_reinstall_keeps_the_pristine_backup(self):
        self.install()
        self.install()
        self.assertEqual(self.read(self.paths.rule_backup), self.RULE)
        self.assertEqual(json.loads(self.read(self.paths.backup))["toolPermission"], "ask")


class TestRuleUpgrade(InstallerTestCase):
    def test_stale_rule_block_is_rewritten(self):
        self.install()
        stale = self.read(self.paths.rule).replace("You MUST invoke", "OLD TEXT")
        self.write(self.paths.rule, stale)
        self.install()
        rule = self.read(self.paths.rule)
        self.assertNotIn("OLD TEXT", rule)
        self.assertIn("You MUST invoke", rule)
        self.assertEqual(rule.count(sam.MARKER_BEGIN), 1)

    def test_upgrade_keeps_surrounding_content(self):
        self.write(self.paths.rule, "# Head\n")
        self.install()
        self.write(self.paths.rule, self.read(self.paths.rule) + "\n# Tail\n")
        self.install()
        rule = self.read(self.paths.rule)
        self.assertTrue(rule.startswith("# Head\n"))
        self.assertTrue(rule.rstrip("\n").endswith("# Tail"))

    def test_stale_subagent_is_rewritten(self):
        self.install()
        self.write(self.paths.agent, "stale\n")
        self.install()
        self.assertEqual(self.read(self.paths.agent), sam.AGENT_MD)


class TestEmptySettingsFile(InstallerTestCase):
    """Regression: an existing '{}' must survive a round trip."""

    def test_pre_existing_empty_settings_file_is_kept(self):
        self.write(self.paths.settings, "{}\n")
        self.install()
        self.revert()
        self.assertTrue(os.path.exists(self.paths.settings))
        self.assertEqual(self.settings(), {})

    def test_installer_created_settings_file_is_removed(self):
        self.install()
        self.revert()
        self.assertFalse(os.path.exists(self.paths.settings))


class TestMarkerHandling(InstallerTestCase):
    def test_stray_end_marker_before_block_is_ignored(self):
        """Regression: find(MARKER_END) from 0 used to leave the rule installed."""
        head = "# notes\n\n" + sam.MARKER_END + "\n"
        self.write(self.paths.rule, head)
        self.install()
        self.revert()
        self.assertEqual(self.read(self.paths.rule), head.rstrip("\n") + "\n")

    def test_duplicate_begin_markers_abort(self):
        self.write(self.paths.rule, sam.RULE_BLOCK + "\n" + sam.RULE_BLOCK)
        with self.assertRaises(sam.AbortError):
            sam.plan_install(self.paths)

    def test_unterminated_block_aborts(self):
        self.write(self.paths.rule, "# notes\n" + sam.MARKER_BEGIN + "\nrule\n")
        with self.assertRaises(sam.AbortError):
            sam.plan_install(self.paths)

    def test_revert_without_install_is_harmless(self):
        self.write(self.paths.rule, "# notes\n")
        self.revert()
        self.assertEqual(self.read(self.paths.rule), "# notes\n")


class TestAbortsBeforeWriting(InstallerTestCase):
    def test_malformed_settings_json_writes_nothing(self):
        self.write(self.paths.settings, '{"theme": "dark",}\n')
        with self.assertRaises(sam.AbortError):
            sam.plan_install(self.paths)
        self.assertFalse(os.path.exists(self.paths.agent))

    def test_non_object_settings_json_aborts(self):
        self.write(self.paths.settings, "[1, 2, 3]\n")
        with self.assertRaises(sam.AbortError):
            sam.plan_install(self.paths)

    def test_unreadable_rule_file_writes_nothing(self):
        """Regression: the subagent used to be written before this blew up."""
        os.makedirs(self.paths.rule)
        with self.assertRaises(sam.AbortError):
            sam.plan_install(self.paths)
        self.assertFalse(os.path.exists(self.paths.agent))

    def test_malformed_settings_json_does_not_stop_revert(self):
        self.install()
        self.write(self.paths.settings, "not json\n")
        with self.assertRaises(sam.AbortError):
            sam.plan_revert(self.paths)
        self.assertTrue(os.path.exists(self.paths.agent))


class TestAtomicWrite(InstallerTestCase):
    def test_failed_write_leaves_the_old_file(self):
        target = os.path.join(self.root, "file.txt")
        self.write(target, "original\n")

        class Boom(Exception):
            pass

        real_replace = os.replace

        def fail(src, dst):
            raise Boom()

        os.replace = fail
        try:
            with self.assertRaises(Boom):
                sam.atomic_write(target, "replacement\n")
        finally:
            os.replace = real_replace

        self.assertEqual(self.read(target), "original\n")
        leftovers = [n for n in os.listdir(self.root) if n.startswith(".auto-mode-")]
        self.assertEqual(leftovers, [])

    def test_writes_lf_line_endings(self):
        target = os.path.join(self.root, "file.txt")
        sam.atomic_write(target, "a\nb\n")
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), b"a\nb\n")


if __name__ == "__main__":
    unittest.main()
