param(
    [Parameter(Mandatory = $true)]
    [string]$BrokerUrl,
    [string]$ApprovalUrl = $BrokerUrl,
    [string]$SiteWindowTitle = "gVisor Hook Dashboard",
    [switch]$Preview,
    [switch]$PreviewCompact
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class ArgusNative {
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_NOACTIVATE = 0x08000000;
    public const int MONITOR_DEFAULTTOPRIMARY = 1;
    public const int SW_RESTORE = 9;

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct MONITORINFO {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public int dwFlags;
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern IntPtr MonitorFromWindow(IntPtr hwnd, int flags);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool GetMonitorInfo(IntPtr monitor, ref MONITORINFO info);

    [DllImport("user32.dll")]
    public static extern int GetWindowLong(IntPtr hwnd, int index);

    [DllImport("user32.dll")]
    public static extern int SetWindowLong(IntPtr hwnd, int index, int value);

    [DllImport("user32.dll")]
    public static extern uint GetDpiForWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hwnd, int command);
}
"@

function ConvertFrom-UnicodeJson {
    param([string]$Json)
    return $Json | ConvertFrom-Json
}

$Text = ConvertFrom-UnicodeJson @'
{
  "message": "\uc0ac\uc6a9\uc790\uc758 \uc2b9\uc778\uc774 \ud544\uc694\ud55c \uc791\uc5c5\uc774 \uc788\uc2b5\ub2c8\ub2e4.",
  "compact": "1\uc2dc\uac04 \ub3d9\uc548 \uc791\uc740 \uc54c\ub9bc\uc73c\ub85c \ubc1b\uae30",
  "shortcut": "\ubc14\ub85c\uac00\uae30",
  "title": "ARGUS \uc2b9\uc778 \uc54c\ub9bc"
}
'@

$StateDirectory = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "ARGUS"
$StatePath = Join-Path $StateDirectory "approval-notifier.json"
$LogPath = Join-Path $StateDirectory "approval-notifier.log"
$Mutex = New-Object Threading.Mutex($false, "Local\ARGUS.WindowsApprovalNotifier")
$HasMutex = $false

function Write-NotifierLog {
    param([string]$Message)
    try {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
        $line = "{0:o} {1}" -f [DateTimeOffset]::Now, $Message
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {
    }
}

function Get-CompactUntil {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        return [DateTimeOffset]::MinValue
    }
    try {
        $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $until = [DateTimeOffset]::Parse([string]$state.compact_until_utc)
        if ($until -gt [DateTimeOffset]::UtcNow) {
            return $until
        }
    } catch {
        Write-NotifierLog "Could not read compact notification state: $($_.Exception.Message)"
    }
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    return [DateTimeOffset]::MinValue
}

function Set-CompactUntil {
    param([DateTimeOffset]$Until)
    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    @{
        compact_until_utc = $Until.UtcDateTime.ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Get-ActiveWorkArea {
    $foreground = [ArgusNative]::GetForegroundWindow()
    $monitor = [ArgusNative]::MonitorFromWindow(
        $foreground,
        [ArgusNative]::MONITOR_DEFAULTTOPRIMARY
    )
    $info = New-Object ArgusNative+MONITORINFO
    $info.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($info)
    if (-not [ArgusNative]::GetMonitorInfo($monitor, [ref]$info)) {
        $workingArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        return @{
            Left = [double]$workingArea.Left
            Top = [double]$workingArea.Top
            Width = [double]$workingArea.Width
            Height = [double]$workingArea.Height
        }
    }
    return @{
        Left = [double]$info.rcWork.Left
        Top = [double]$info.rcWork.Top
        Width = [double]($info.rcWork.Right - $info.rcWork.Left)
        Height = [double]($info.rcWork.Bottom - $info.rcWork.Top)
    }
}

function Set-NoActivate {
    param([System.Windows.Window]$Window)
    $helper = New-Object System.Windows.Interop.WindowInteropHelper($Window)
    $style = [ArgusNative]::GetWindowLong($helper.Handle, [ArgusNative]::GWL_EXSTYLE)
    [ArgusNative]::SetWindowLong(
        $helper.Handle,
        [ArgusNative]::GWL_EXSTYLE,
        ($style -bor [ArgusNative]::WS_EX_NOACTIVATE)
    ) | Out-Null
}

function Position-Window {
    param(
        [System.Windows.Window]$Window,
        [bool]$Compact
    )
    $work = Get-ActiveWorkArea
    $helper = New-Object System.Windows.Interop.WindowInteropHelper($Window)
    $dpi = [ArgusNative]::GetDpiForWindow($helper.Handle)
    if ($dpi -eq 0) {
        $dpi = 96
    }
    $deviceToDip = 96.0 / [double]$dpi
    $left = $work.Left * $deviceToDip
    $top = $work.Top * $deviceToDip
    $width = $work.Width * $deviceToDip
    $height = $work.Height * $deviceToDip
    if ($Compact) {
        $Window.Left = $left + $width - $Window.ActualWidth - 20
        $Window.Top = $top + $height - $Window.ActualHeight - 20
    } else {
        $Window.Left = $left + (($width - $Window.ActualWidth) / 2)
        $Window.Top = $top + (($height - $Window.ActualHeight) / 2)
    }
}

function Get-VisibleToastWindows {
    return @($script:ToastWindows | Where-Object {
        $null -ne $_ -and $_.IsVisible
    })
}

function Position-ToastWindows {
    $windows = @(Get-VisibleToastWindows)
    if ($windows.Count -eq 0) {
        return
    }

    $work = Get-ActiveWorkArea
    $helper = New-Object System.Windows.Interop.WindowInteropHelper($windows[0])
    $dpi = [ArgusNative]::GetDpiForWindow($helper.Handle)
    if ($dpi -eq 0) {
        $dpi = 96
    }
    $deviceToDip = 96.0 / [double]$dpi
    $left = $work.Left * $deviceToDip
    $top = $work.Top * $deviceToDip
    $width = $work.Width * $deviceToDip
    $height = $work.Height * $deviceToDip
    $cursorBottom = $top + $height - 20

    # The list is oldest-first, so older notifications stay near the taskbar
    # and each newly added notification is positioned above them.
    foreach ($toast in $windows) {
        $toast.Left = $left + $width - $toast.ActualWidth - 20
        $toast.Top = $cursorBottom - $toast.ActualHeight
        $cursorBottom = $toast.Top - 12
    }
}

function Close-AllToastWindows {
    $windows = @(Get-VisibleToastWindows)
    $script:ToastWindows.Clear()
    foreach ($toast in $windows) {
        try {
            # Keep the WPF dispatcher alive after the last visible toast is
            # dismissed so future approval events can create new windows.
            $toast.Hide()
        } catch {
            Write-NotifierLog "Could not hide toast notification: $($_.Exception.Message)"
        }
    }
}

function Focus-ExistingApprovalSite {
    $targetTitle = $(if ($SiteWindowTitle) { $SiteWindowTitle } else { "gVisor Hook Dashboard" })
    $browserNames = @("chrome", "msedge", "firefox", "brave")
    $tabCondition = New-Object Windows.Automation.PropertyCondition(
        [Windows.Automation.AutomationElement]::ControlTypeProperty,
        [Windows.Automation.ControlType]::TabItem
    )

    foreach ($process in Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -in $browserNames -and $_.MainWindowHandle -ne 0
    }) {
        try {
            $browserWindow = [Windows.Automation.AutomationElement]::FromHandle(
                $process.MainWindowHandle
            )
            $tabs = $browserWindow.FindAll(
                [Windows.Automation.TreeScope]::Descendants,
                $tabCondition
            )
            foreach ($tab in $tabs) {
                if ($tab.Current.Name.IndexOf(
                    $targetTitle,
                    [StringComparison]::OrdinalIgnoreCase
                ) -lt 0) {
                    continue
                }

                $selection = $tab.GetCurrentPattern(
                    [Windows.Automation.SelectionItemPattern]::Pattern
                )
                $selection.Select()
                [ArgusNative]::ShowWindow(
                    $process.MainWindowHandle,
                    [ArgusNative]::SW_RESTORE
                ) | Out-Null
                [ArgusNative]::SetForegroundWindow($process.MainWindowHandle) | Out-Null
                return $true
            }
        } catch {
            Write-NotifierLog "Could not inspect browser tabs: $($_.Exception.Message)"
        }
    }
    return $false
}

function Open-ApprovalSite {
    if (Focus-ExistingApprovalSite) {
        return
    }
    $separator = $(if ($ApprovalUrl.Contains("?")) { "&" } else { "?" })
    $cacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $targetUrl = "{0}{1}argus_notification=desktop&ts={2}" -f $ApprovalUrl, $separator, $cacheBuster
    Start-Process $targetUrl
}

function New-ApprovalWindow {
    param(
        [bool]$Compact,
        [DateTimeOffset]$OccurredAt
    )

    $window = New-Object System.Windows.Window
    $window.Title = $Text.title
    $window.WindowStyle = [System.Windows.WindowStyle]::None
    $window.ResizeMode = [System.Windows.ResizeMode]::NoResize
    $window.SizeToContent = [System.Windows.SizeToContent]::Height
    $window.ShowInTaskbar = $false
    $window.Topmost = $true
    $window.ShowActivated = $false
    $window.AllowsTransparency = $true
    $window.Background = [System.Windows.Media.Brushes]::Transparent
    $window.Width = $(if ($Compact) { 390 } else { 430 })

    $border = New-Object System.Windows.Controls.Border
    $border.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFFFFF")
    $border.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#D8DEE9")
    $border.BorderThickness = New-Object System.Windows.Thickness(1)
    $border.CornerRadius = New-Object System.Windows.CornerRadius(10)
    $border.Padding = New-Object System.Windows.Thickness(18)
    $border.Effect = New-Object System.Windows.Media.Effects.DropShadowEffect
    $border.Effect.BlurRadius = 24
    $border.Effect.Opacity = 0.22
    $border.Effect.ShadowDepth = 5

    $grid = New-Object System.Windows.Controls.Grid
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
    if (-not $Compact) {
        $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
    }
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

    $header = New-Object System.Windows.Controls.Grid
    $header.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition))
    $closeColumn = New-Object System.Windows.Controls.ColumnDefinition
    $closeColumn.Width = New-Object System.Windows.GridLength(30)
    $header.ColumnDefinitions.Add($closeColumn)
    [System.Windows.Controls.Grid]::SetRow($header, 0)

    $timeText = New-Object System.Windows.Controls.TextBlock
    $timeText.Text = $OccurredAt.ToLocalTime().ToString("yyyy. M. d. tt h:mm:ss")
    $timeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#7A808B")
    $timeText.FontSize = 13
    $timeText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $header.Children.Add($timeText) | Out-Null

    $closeButton = New-Object System.Windows.Controls.Button
    $closeButton.Content = [char]0x00D7
    $closeButton.FontSize = 20
    $closeButton.FontWeight = [System.Windows.FontWeights]::SemiBold
    $closeButton.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#111827")
    $closeButton.Background = [System.Windows.Media.Brushes]::Transparent
    $closeButton.BorderThickness = New-Object System.Windows.Thickness(0)
    $closeButton.Cursor = [System.Windows.Input.Cursors]::Hand
    [System.Windows.Controls.Grid]::SetColumn($closeButton, 1)
    $header.Children.Add($closeButton) | Out-Null
    $grid.Children.Add($header) | Out-Null

    $message = New-Object System.Windows.Controls.TextBlock
    $message.Text = $Text.message
    $message.FontSize = $(if ($Compact) { 16 } else { 20 })
    $message.FontWeight = [System.Windows.FontWeights]::Bold
    $message.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#111827")
    $message.Margin = New-Object System.Windows.Thickness(0, 18, 0, 0)
    $message.TextWrapping = [System.Windows.TextWrapping]::Wrap
    [System.Windows.Controls.Grid]::SetRow($message, 1)
    $grid.Children.Add($message) | Out-Null

    $checkbox = $null
    $buttonRow = 2
    if (-not $Compact) {
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $Text.compact
        $checkbox.FontSize = 14
        $checkbox.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#30343B")
        $checkbox.Margin = New-Object System.Windows.Thickness(0, 22, 0, 0)
        [System.Windows.Controls.Grid]::SetRow($checkbox, 2)
        $grid.Children.Add($checkbox) | Out-Null
        $buttonRow = 3
    }

    $shortcut = New-Object System.Windows.Controls.Button
    $shortcut.Content = $Text.shortcut
    $shortcut.Height = 42
    $shortcut.Margin = New-Object System.Windows.Thickness(0, 22, 0, 0)
    $shortcut.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#13213A")
    $shortcut.Foreground = [System.Windows.Media.Brushes]::White
    $shortcut.BorderThickness = New-Object System.Windows.Thickness(0)
    $shortcut.FontSize = 14
    $shortcut.FontWeight = [System.Windows.FontWeights]::Bold
    $shortcut.Cursor = [System.Windows.Input.Cursors]::Hand
    [System.Windows.Controls.Grid]::SetRow($shortcut, $buttonRow)
    $grid.Children.Add($shortcut) | Out-Null

    $border.Child = $grid
    $window.Content = $border
    $window.Add_SourceInitialized({
        Set-NoActivate -Window $window
    }.GetNewClosure())
    $window.Add_ContentRendered({
        try {
            if ($Compact) {
                Position-ToastWindows
            } else {
                Position-Window -Window $window -Compact:$false
            }
        } catch {
            Write-NotifierLog "Could not position notification window: $($_.Exception.Message)"
        }
    }.GetNewClosure())
    $shortcut.Add_Click({
        try {
            Open-ApprovalSite
            if ($Compact) {
                Close-AllToastWindows
            } else {
                $window.Close()
            }
        } catch {
            Write-NotifierLog "Shortcut action failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())
    $closeButton.Add_Click({
        try {
            if ($Compact) {
                Close-AllToastWindows
            } else {
                $window.Close()
            }
        } catch {
            Write-NotifierLog "Close action failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())
    $window.Add_Closing({
        if ($null -ne $checkbox -and $checkbox.IsChecked) {
            Set-CompactUntil ([DateTimeOffset]::UtcNow.AddHours(1))
        }
    }.GetNewClosure())
    $window.Add_Closed({
        if ($Compact) {
            $script:ToastWindows.Remove($window) | Out-Null
            try {
                Position-ToastWindows
            } catch {
                Write-NotifierLog "Could not reposition toast notifications: $($_.Exception.Message)"
            }
        } elseif ($script:ModalWindow -eq $window) {
            $script:ModalWindow = $null
        }
    }.GetNewClosure())
    return $window
}

function Get-PendingEvents {
    $response = Invoke-RestMethod `
        -Method Get `
        -Uri ($BrokerUrl.TrimEnd("/") + "/api/events") `
        -TimeoutSec 3
    if ($response.type -ne "snapshot") {
        return @()
    }
    return @($response.payload.events | Where-Object { $_.status -eq "pending" })
}

try {
    $HasMutex = $Mutex.WaitOne(0, $false)
    if (-not $HasMutex) {
        exit 0
    }

    $script:ToastWindows = New-Object System.Collections.ArrayList
    $script:ModalWindow = $null

    if ($Preview -or $PreviewCompact) {
        $previewWindow = New-ApprovalWindow -Compact:$PreviewCompact.IsPresent -OccurredAt ([DateTimeOffset]::Now)
        if ($PreviewCompact) {
            $script:ToastWindows.Add($previewWindow) | Out-Null
        }
        $previewWindow.ShowDialog() | Out-Null
        exit 0
    }

    $application = New-Object System.Windows.Application
    $application.ShutdownMode = [System.Windows.ShutdownMode]::OnExplicitShutdown
    $script:Seen = New-Object "System.Collections.Generic.HashSet[string]"
    $script:LastConnectionError = ""

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        try {
            $events = @(Get-PendingEvents)
            $pendingIds = New-Object "System.Collections.Generic.HashSet[string]"
            foreach ($event in $events) {
                $pendingIds.Add([string]$event.id) | Out-Null
            }
            $script:Seen.RemoveWhere([Predicate[string]]{
                param($id)
                return -not $pendingIds.Contains($id)
            }) | Out-Null

            $newEvents = @($events | Where-Object {
                -not $script:Seen.Contains([string]$_.id)
            } | Sort-Object started_at)

            if ($newEvents.Count -gt 0) {
                $compact = (Get-CompactUntil) -gt [DateTimeOffset]::UtcNow
                if ($compact) {
                    foreach ($newEvent in $newEvents) {
                        $script:Seen.Add([string]$newEvent.id) | Out-Null
                        $occurredAt = [DateTimeOffset]::Now
                        try {
                            $occurredAt = [DateTimeOffset]::Parse([string]$newEvent.started_at)
                        } catch {
                        }
                        $toast = New-ApprovalWindow -Compact:$true -OccurredAt $occurredAt
                        $script:ToastWindows.Add($toast) | Out-Null
                        $toast.Show()
                    }
                    Position-ToastWindows
                } elseif ($null -eq $script:ModalWindow -or -not $script:ModalWindow.IsVisible) {
                    $newEvent = $newEvents[0]
                    $script:Seen.Add([string]$newEvent.id) | Out-Null
                    $occurredAt = [DateTimeOffset]::Now
                    try {
                        $occurredAt = [DateTimeOffset]::Parse([string]$newEvent.started_at)
                    } catch {
                    }
                    $script:ModalWindow = New-ApprovalWindow -Compact:$false -OccurredAt $occurredAt
                    $script:ModalWindow.Show()
                }
            }
            $script:LastConnectionError = ""
        } catch {
            $message = $_.Exception.Message
            if ($message -ne $script:LastConnectionError) {
                Write-NotifierLog "Broker polling failed: $message"
                $script:LastConnectionError = $message
            }
        }
    })
    $timer.Start()
    $application.Run() | Out-Null
} catch {
    Write-NotifierLog "Notifier stopped: $($_.Exception.ToString())"
    exit 1
} finally {
    if ($HasMutex) {
        $Mutex.ReleaseMutex()
    }
    $Mutex.Dispose()
}
