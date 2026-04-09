# gVisor Hook MVP

This repository wraps an agent CLI in a custom gVisor runtime and exposes syscall approvals through a local web UI.

## What it does

- Runs an agent command discovered from host `PATH` inside `runsc`
- Leaves the terminal CLI experience intact by relaying the sandbox PTY
- Hooks write-oriented file syscalls and `execve`
- Pauses those syscalls until the browser UI approves or denies them
- Returns `EPERM` on deny or timeout

## Repository layout

- `gvisor_hook/`: Python launcher, broker, web UI, OCI bundle generation
- `third_party/gvisor/`: vendored gVisor source with syscall approval patches
- `scripts/build_runsc.sh`: builds the patched `runsc`
- `tests/test_broker.py`: broker IPC regression tests

## Build the custom runsc

```bash
cd /home/kimji/workspace/gvisorHook
./scripts/build_runsc.sh
```

If you want to format the Go patches first:

```bash
./scripts/format_gvisor_go.sh
```

## Launch the MVP

```bash
cd /home/kimji/workspace/gvisorHook
python3 -m gvisor_hook launch --agent-cmd interpreter --workdir /home/kimji/workspace/gvisorHook --web-port 8080
```

Then open `http://127.0.0.1:8080`.

If the launcher cannot find a config directory automatically, pass one explicitly:

```bash
python3 -m gvisor_hook launch --agent-cmd claude --config-mount ~/.claude --workdir /home/kimji/workspace/gvisorHook
```

## Current syscall scope

- `open/openat/creat` with write intent
- `write/writev/pwrite64`
- `mkdir/mkdirat`
- `unlink/unlinkat`
- `rmdir`
- `rename/renameat/renameat2`
- `execve/execveat`

## Notes

- The current MVP uses host `/` as a read-only OCI root and binds the chosen workdir read-write. The selected agent binary is bind-mounted from the host into the sandbox.
- If the web UI is unreachable or no decision arrives before timeout, the syscall is denied with `EPERM`.
- Python-based agents may also need their `site-packages` directories mounted. The launcher auto-detects those when the command is a Python entrypoint, and `--python-site-packages` can override the detected path.
