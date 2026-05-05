from __future__ import annotations

import subprocess
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock

from gvisor_hook.launcher import (
    agent_command_name,
    find_mitmdump_binary,
    find_mitmdump_command,
    launch,
    resolve_agent_argv_and_mounts,
    spawn_mitmdump,
    wait_for_tcp_ready,
)


class LauncherTests(unittest.TestCase):
    def test_agent_command_name_uses_invoked_command(self) -> None:
        self.assertEqual(agent_command_name(["codex", "exec"]), "codex")
        self.assertEqual(agent_command_name(["gemini"]), "gemini")
        self.assertEqual(agent_command_name(["/opt/bin/custom-agent", "--flag"]), "custom-agent")
        self.assertEqual(agent_command_name(["node", "/opt/agent/bin/agent.js"]), "agent.js")

    def test_launch_proxy_mode_defaults_to_all(self) -> None:
        from gvisor_hook.cli import build_parser

        args = build_parser().parse_args(["launch", "--workdir", "/tmp/workspace"])

        self.assertEqual(args.proxy_mode, "all")

    def test_launch_keeps_agent_cmd_for_generic_resolution(self) -> None:
        args = mock.Mock(
            workdir="/tmp/workspace",
            agent_cmd="codex --version",
            prompt=None,
        )

        with (
            mock.patch("gvisor_hook.launcher.Path.is_dir", return_value=True),
            mock.patch("gvisor_hook.launcher.make_runtime_dir", side_effect=RuntimeError("stop after argv")),
            mock.patch("gvisor_hook.launcher.shlex.split", wraps=__import__("shlex").split) as split_mock,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after argv"):
                launch(args)

        split_mock.assert_called_once_with("codex --version")

    def test_bundle_env_does_not_proxy_all_external_http_by_default(self) -> None:
        from gvisor_hook.bundle import build_process_env

        env = build_process_env(
            "/tmp/agent-home",
        )

        self.assertNotIn("HTTP_PROXY=http://127.0.0.1:12345", env)
        self.assertFalse(any(entry.startswith("HTTPS_PROXY=") for entry in env))
        self.assertFalse(any(entry.startswith("ALL_PROXY=") for entry in env))

    def test_bundle_env_routes_external_http_through_mitm_proxy_when_requested(self) -> None:
        from gvisor_hook.bundle import build_process_env

        env = build_process_env(
            "/tmp/agent-home",
            upstream_proxy_url="http://127.0.0.1:12345",
        )

        self.assertIn("HTTP_PROXY=http://127.0.0.1:12345", env)
        self.assertIn("HTTPS_PROXY=http://127.0.0.1:12345", env)
        self.assertIn("ALL_PROXY=http://127.0.0.1:12345", env)
        no_proxy = next(entry for entry in env if entry.startswith("NO_PROXY="))
        self.assertIn("127.0.0.1", no_proxy)
        self.assertIn("localhost", no_proxy)
        self.assertNotIn("example.com", no_proxy)

        env = build_process_env(
            "/tmp/agent-home",
            upstream_proxy_url="http://127.0.0.1:12345",
            proxy_bypass_hosts=("127.0.0.1", "localhost", "metadata.internal"),
            trusted_ca_cert_path="/tmp/mitmproxy/mitmproxy-ca-cert.pem",
        )
        no_proxy = next(entry for entry in env if entry.startswith("NO_PROXY="))
        self.assertIn("127.0.0.1", no_proxy)
        self.assertIn("localhost", no_proxy)
        self.assertIn("metadata.internal", no_proxy)
        self.assertIn("NODE_EXTRA_CA_CERTS=/tmp/mitmproxy/mitmproxy-ca-cert.pem", env)
        self.assertIn("REQUESTS_CA_BUNDLE=/tmp/mitmproxy/mitmproxy-ca-cert.pem", env)
        self.assertIn("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/tmp/mitmproxy/mitmproxy-ca-cert.pem", env)

    def test_bundle_env_forwards_generic_credential_suffixes(self) -> None:
        from gvisor_hook.bundle import build_process_env

        with mock.patch.dict(
            os.environ,
            {
                "CUSTOM_AGENT_API_KEY": "api-key",
                "CUSTOM_AGENT_AUTH_TOKEN": "auth-token",
                "CUSTOM_AGENT_BASE_URL": "https://gateway.example.test/v1",
                "CUSTOM_AGENT_ENDPOINT": "https://endpoint.example.test",
                "CUSTOM_AGENT_REGION": "ignored",
            },
            clear=False,
        ):
            env = build_process_env("/tmp/agent-home")

        self.assertIn("CUSTOM_AGENT_API_KEY=api-key", env)
        self.assertIn("CUSTOM_AGENT_AUTH_TOKEN=auth-token", env)
        self.assertIn("CUSTOM_AGENT_BASE_URL=https://gateway.example.test/v1", env)
        self.assertIn("CUSTOM_AGENT_ENDPOINT=https://endpoint.example.test", env)
        self.assertNotIn("CUSTOM_AGENT_REGION=ignored", env)

    def test_spawn_mitmdump_has_no_provider_specific_ignore_hosts_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            session_root = temp_path / "session"
            dataset_root = temp_path / "dataset"
            session_root.mkdir()
            dataset_root.mkdir()
            dataset_session = mock.Mock(
                session_root=session_root,
                dataset_root=dataset_root,
                session_id="session-test",
            )

            with mock.patch("gvisor_hook.launcher.subprocess.Popen") as popen_mock:
                spawn_mitmdump(
                    ["/usr/bin/python3.10", "/usr/bin/mitmdump"],
                    12345,
                    temp_path / "mitm.log",
                    temp_path / "llm.ndjson",
                    dataset_session,
                )

            command = popen_mock.call_args.args[0]
            popen_mock.call_args.kwargs["stdout"].close()
            self.assertNotIn("--ignore-hosts", command)

    def test_spawn_mitmdump_uses_configured_ignore_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            session_root = temp_path / "session"
            dataset_root = temp_path / "dataset"
            session_root.mkdir()
            dataset_root.mkdir()
            dataset_session = mock.Mock(
                session_root=session_root,
                dataset_root=dataset_root,
                session_id="session-test",
            )

            with (
                mock.patch("gvisor_hook.launcher.subprocess.Popen") as popen_mock,
                mock.patch.dict("gvisor_hook.launcher.os.environ", {"GVISOR_HOOK_MITM_IGNORE_HOSTS": "example.com,metadata.internal"}),
            ):
                spawn_mitmdump(
                    ["/usr/bin/python3.10", "/usr/bin/mitmdump"],
                    12345,
                    temp_path / "mitm.log",
                    temp_path / "llm.ndjson",
                    dataset_session,
                )

            command = popen_mock.call_args.args[0]
            popen_mock.call_args.kwargs["stdout"].close()
            ignore_index = command.index("--ignore-hosts") + 1
            ignore_pattern = command[ignore_index]
            self.assertIn("example\\.com", ignore_pattern)
            self.assertIn("metadata\\.internal", ignore_pattern)

    def test_resolve_agent_argv_mounts_shebang_bundle_and_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            home_dir = temp_path / "home"
            bundle_dir = temp_path / "bundle"
            node_dir = temp_path / "node-bin"
            agent_script = bundle_dir / "agent-cli.js"
            chunk = bundle_dir / "agent-cli-CHUNK.js"
            node = node_dir / "node"
            config_dir = home_dir / ".agent-cli"
            bundle_dir.mkdir()
            node_dir.mkdir()
            config_dir.mkdir(parents=True)
            agent_script.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            chunk.write_text("export {}\n", encoding="utf-8")
            node.write_text("", encoding="utf-8")
            node.chmod(0o755)

            def which(name: str) -> str | None:
                if name == "agent-cli":
                    return str(agent_script)
                if name == "node":
                    return str(node)
                return None

            with (
                mock.patch("gvisor_hook.launcher.shutil.which", side_effect=which),
                mock.patch("gvisor_hook.launcher.Path.home", return_value=home_dir),
            ):
                argv, mounts = resolve_agent_argv_and_mounts(["agent-cli", "--version"], "/tmp/agent-home")

            self.assertEqual(argv, ["/tmp/agent/bin/agent-cli.js", "--version"])
            self.assertIn(
                {
                    "destination": "/tmp/agent/bin",
                    "type": "bind",
                    "source": str(bundle_dir.resolve()),
                    "options": ["rbind", "ro"],
                },
                mounts,
            )
            self.assertIn(
                {
                    "destination": "/tmp/agent/bin/node",
                    "type": "bind",
                    "source": str(node.resolve()),
                    "options": ["bind", "ro"],
                },
                mounts,
            )
            self.assertIn(
                {
                    "destination": "/tmp/agent-home/.agent-cli",
                    "type": "bind",
                    "source": str(config_dir),
                    "options": ["rbind", "rw"],
                },
                mounts,
            )

    def test_resolve_agent_argv_mounts_node_for_shell_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            wrapper_dir = temp_path / "wrapper"
            node_dir = temp_path / "node-bin"
            wrapper = wrapper_dir / "agent-cli"
            node = node_dir / "node"
            wrapper_dir.mkdir()
            node_dir.mkdir()
            wrapper.write_text("#!/bin/sh\nexec node \"$basedir/tool\" \"$@\"\n", encoding="utf-8")
            node.write_text("", encoding="utf-8")
            wrapper.chmod(0o755)
            node.chmod(0o755)

            def which(name: str) -> str | None:
                if name == "agent-cli":
                    return str(wrapper)
                if name == "node":
                    return str(node)
                return None

            with mock.patch("gvisor_hook.launcher.shutil.which", side_effect=which):
                argv, mounts = resolve_agent_argv_and_mounts(["agent-cli"], "/tmp/agent-home")

            self.assertEqual(argv, ["/tmp/agent/bin/agent-cli"])
            self.assertIn(
                {
                    "destination": "/tmp/agent/bin/node",
                    "type": "bind",
                    "source": str(node.resolve()),
                    "options": ["bind", "ro"],
                },
                mounts,
            )

    def test_resolve_agent_argv_prefers_node_next_to_invoked_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            bin_dir = temp_path / "bin"
            node_modules = temp_path / "lib" / "node_modules"
            package_bin = node_modules / "tool" / "bin"
            invoked = bin_dir / "agent-cli"
            node = bin_dir / "node"
            target = package_bin / "agent-cli.js"
            bin_dir.mkdir()
            package_bin.mkdir(parents=True)
            target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            node.write_text("", encoding="utf-8")
            target.chmod(0o755)
            node.chmod(0o755)
            invoked.symlink_to(target)

            def which(name: str) -> str | None:
                if name == "agent-cli":
                    return str(invoked)
                if name == "node":
                    return "/usr/bin/node"
                return None

            with mock.patch("gvisor_hook.launcher.shutil.which", side_effect=which):
                argv, mounts = resolve_agent_argv_and_mounts(["agent-cli"], "/tmp/agent-home")

            self.assertEqual(argv, ["/tmp/agent/node_modules/tool/bin/agent-cli.js"])
            self.assertIn(
                {
                    "destination": "/tmp/agent/bin/node",
                    "type": "bind",
                    "source": str(node.resolve()),
                    "options": ["bind", "ro"],
                },
                mounts,
            )
            self.assertIn(
                {
                    "destination": "/tmp/agent/node_modules",
                    "type": "bind",
                    "source": str(node_modules),
                    "options": ["rbind", "ro"],
                },
                mounts,
            )

    def test_resolve_agent_argv_rejects_missing_node_for_shell_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            wrapper = temp_path / "agent-cli"
            wrapper.write_text("#!/bin/sh\nexec node \"$basedir/tool\" \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o755)

            def which(name: str) -> str | None:
                if name == "agent-cli":
                    return str(wrapper)
                if name == "node":
                    return "/usr/bin/node"
                return None

            with mock.patch("gvisor_hook.launcher.shutil.which", side_effect=which):
                with self.assertRaisesRegex(FileNotFoundError, "no executable node"):
                    resolve_agent_argv_and_mounts(["agent-cli"], "/tmp/agent-home")

    @mock.patch("gvisor_hook.launcher.shutil.which", return_value=None)
    @mock.patch("gvisor_hook.launcher.Path.home", return_value=Path("/tmp/missing-home"))
    def test_find_mitmdump_binary_does_not_treat_cwd_as_candidate(
        self, _home_mock: mock.Mock, _which_mock: mock.Mock
    ) -> None:
        with self.assertRaises(FileNotFoundError):
            find_mitmdump_binary()

    def test_find_mitmdump_command_uses_python_fallback_for_python3_script(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            home_dir = temp_path / "home"
            mitmdump_bin = temp_path / "mitmdump"
            python_bin = temp_path / "python3.10"
            home_dir.mkdir()
            mitmdump_bin.write_text("#!/usr/bin/python3\n", encoding="utf-8")
            python_bin.write_text("", encoding="utf-8")
            mitmdump_bin.chmod(0o755)
            python_bin.chmod(0o755)

            def which(name: str) -> str | None:
                if name == "mitmdump":
                    return str(mitmdump_bin)
                if name == "python3.10":
                    return str(python_bin)
                return None

            def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if command == [str(mitmdump_bin), "--version"]:
                    return subprocess.CompletedProcess(command, 1, "", "missing _cffi_backend")
                if command == [str(python_bin.resolve()), str(mitmdump_bin), "--version"]:
                    return subprocess.CompletedProcess(command, 0, "Mitmproxy: 6.0.2", "")
                return subprocess.CompletedProcess(command, 1, "", "unexpected command")

            with (
                mock.patch("gvisor_hook.launcher.Path.home", return_value=home_dir),
                mock.patch("gvisor_hook.launcher.shutil.which", side_effect=which),
                mock.patch("gvisor_hook.launcher.subprocess.run", side_effect=run),
            ):
                self.assertEqual(
                    find_mitmdump_command(),
                    [str(python_bin.resolve()), str(mitmdump_bin)],
                )

    def test_wait_for_tcp_ready_reports_child_exit_with_log_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            log_path = Path(tempdir) / "mitmproxy.log"
            log_path.write_text("mitmdump failed\nmissing dependency\n", encoding="utf-8")
            child = subprocess.Popen(["/bin/sh", "-c", "exit 7"])
            child.wait(timeout=5)

            with self.assertRaisesRegex(RuntimeError, "mitmdump exited before becoming ready"):
                try:
                    wait_for_tcp_ready(
                        "127.0.0.1",
                        9,
                        timeout=1,
                        child=child,
                        log_path=log_path,
                        service_name="mitmdump",
                    )
                except RuntimeError as exc:
                    self.assertIn("missing dependency", str(exc))
                    raise


if __name__ == "__main__":
    unittest.main()
