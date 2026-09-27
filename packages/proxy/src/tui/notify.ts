/**
 * Best-effort desktop toast for Live security alerts (DENY / DLP / rate-limit /
 * idle). It only SHOWS a notification — clicking it does nothing. Every platform
 * uses a tool it already ships with, and any failure is swallowed so a
 * notification never disturbs the TUI.
 *
 *   Linux   — notify-send (libnotify; present on GNOME/KDE desktops)
 *   Windows — a NotifyIcon balloon via built-in PowerShell
 *   macOS   — a built-in osascript notification
 */
import { spawn } from 'node:child_process';

/** Fire a plain desktop toast. No-op-safe: missing tools just mean no toast. */
export function desktopNotify(title: string, msg: string): void {
  try {
    if (process.platform === 'linux') {
      const p = spawn('notify-send', ['-a', 'SolonGate', title, msg], { stdio: 'ignore', detached: true });
      p.on('error', () => {});
      p.unref();
    } else if (process.platform === 'win32') {
      const q = (s: string) => s.replace(/'/g, "''");
      const ps =
        "Add-Type -AssemblyName System.Windows.Forms;" +
        "Add-Type -AssemblyName System.Drawing;" +
        "$n=New-Object System.Windows.Forms.NotifyIcon;" +
        "$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;" +
        `$n.ShowBalloonTip(6000,'${q(title)}','${q(msg)}',[System.Windows.Forms.ToolTipIcon]::Warning);` +
        "Start-Sleep -Milliseconds 6500;$n.Dispose()";
      const p = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], { stdio: 'ignore', detached: true, windowsHide: true });
      p.on('error', () => {});
      p.unref();
    } else if (process.platform === 'darwin') {
      const esc = (s: string) => s.replace(/"/g, '\\"');
      const p = spawn('osascript', ['-e', `display notification "${esc(msg)}" with title "${esc(title)}"`], { stdio: 'ignore', detached: true });
      p.on('error', () => {});
      p.unref();
    }
  } catch { /* best-effort: never disturb the TUI */ }
}
