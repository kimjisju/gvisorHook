from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gvisor_hook.launcher import (
    MountSpec,
    iter_config_dir_candidates,
    parse_shebang_command,
    resolve_python_from_shebang,
    sanitize_name,
)


class LauncherHelpersTests(unittest.TestCase):
    def test_sanitize_name(self) -> None:
        self.assertEqual(sanitize_name("Open Interpreter"), "open-interpreter")
        self.assertEqual(sanitize_name("claude"), "claude")

    def test_iter_config_dir_candidates(self) -> None:
        home_dir = Path("/tmp/demo-home")
        candidates = iter_config_dir_candidates("claude", home_dir)
        self.assertEqual(
            candidates,
            [
                home_dir / ".claude",
                home_dir / "claude",
                home_dir / ".config" / "claude",
            ],
        )

    def test_parse_shebang_command(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            script_path = Path(tempdir) / "demo"
            script_path.write_text("#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")
            self.assertEqual(parse_shebang_command(script_path), ["/usr/bin/env", "python3"])

    def test_resolve_python_from_shebang(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            script_path = Path(tempdir) / "demo"
            script_path.write_text("#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")
            python_bin = resolve_python_from_shebang(script_path)
            self.assertIsNotNone(python_bin)
            self.assertIn("python", python_bin.name.lower())

    def test_mount_spec_to_oci_mount(self) -> None:
        mount = MountSpec(source=Path("/tmp/source"), destination="/tmp/dest", recursive=False, writable=True)
        self.assertEqual(
            mount.to_oci_mount(),
            {
                "destination": "/tmp/dest",
                "type": "bind",
                "source": "/tmp/source",
                "options": ["bind", "rw"],
            },
        )


if __name__ == "__main__":
    unittest.main()
