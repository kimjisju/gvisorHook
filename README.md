# gVisor Hook MVP

This repository wraps `Open Interpreter` in a custom gVisor runtime and exposes syscall approvals through a local web UI.

## What it does

- Runs `/home/kimjisu/.local/bin/interpreter` inside `runsc`
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
cd /home/kimjisu/gvisorHook
./scripts/build_runsc.sh
```

If you want to format the Go patches first:

```bash
./scripts/format_gvisor_go.sh
```

## Launch the MVP

```bash
cd /home/kimjisu/gvisorHook
python3 -m gvisor_hook launch --workdir /home/kimjisu/gvisorHook --web-port 8080
```

Then open `http://127.0.0.1:8080`.

## Current syscall scope

- `open/openat/creat` with write intent
- `write/writev/pwrite64`
- `mkdir/mkdirat`
- `unlink/unlinkat`
- `rmdir`
- `rename/renameat/renameat2`
- `execve/execveat`

## Notes

- The current MVP uses host `/` as a read-only OCI root and binds the chosen workdir read-write. That keeps the interpreter installation available without repackaging a full rootfs.
- If the web UI is unreachable or no decision arrives before timeout, the syscall is denied with `EPERM`.
- `Open Interpreter` source is untouched; only the launcher/runtime path is changed.
