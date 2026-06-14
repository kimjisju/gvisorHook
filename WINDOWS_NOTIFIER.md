# Windows Approval Notifier

When `launch` runs under WSL and `powershell.exe` is available, ARGUS starts
`scripts/windows_approval_notifier.ps1` as a separate Windows process. Pending
approvals appear above other applications without activating the notification
window, and the shortcut button opens `http://127.0.0.1:<web-port>`.

The compact notification option stores its UTC expiration time in:

```text
%LOCALAPPDATA%\ARGUS\approval-notifier.json
```

For the next hour, notices use the active monitor's lower-right working area.
The setting survives restarts and expires automatically. A named Windows mutex
prevents duplicate notifier processes.

Use `--no-windows-notifier` to disable automatic startup.

To preview the centered window from Windows PowerShell:

```powershell
powershell.exe -Sta -ExecutionPolicy Bypass `
  -File scripts\windows_approval_notifier.ps1 `
  -BrokerUrl http://127.0.0.1:8080 `
  -Preview
```
