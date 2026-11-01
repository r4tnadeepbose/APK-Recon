param(
    [Parameter(Mandatory=$true)][string]$Title,
    [Parameter(Mandatory=$true)][string]$Out,
    [switch]$Exact
)

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class ShotCap2 {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  public struct RECT { public int Left, Top, Right, Bottom; }
}
'@

$script:found = [IntPtr]::Zero
$script:best = 0
$callback = [ShotCap2+EnumProc]{
    param($h, $param)
    if (-not [ShotCap2]::IsWindowVisible($h)) { return $true }
    $sb = New-Object System.Text.StringBuilder 512
    [void][ShotCap2]::GetWindowTextW($h, $sb, 512)
    $text = $sb.ToString()
    if ($Exact) { if ($text -ne $Title) { return $true } }
    else { if ($text -notlike "*$Title*") { return $true } }
    $rect = New-Object ShotCap2+RECT
    [void][ShotCap2]::GetWindowRect($h, [ref]$rect)
    $area = ($rect.Right - $rect.Left) * ($rect.Bottom - $rect.Top)
    if ($area -gt $script:best) { $script:best = $area; $script:found = $h }
    return $true
}
[void][ShotCap2]::EnumWindows($callback, [IntPtr]::Zero)
if ($script:found -eq [IntPtr]::Zero) { Write-Output "window not found: $Title"; exit 1 }

$r = New-Object ShotCap2+RECT
[void][ShotCap2]::GetWindowRect($script:found, [ref]$r)
$w = $r.Right - $r.Left
$h = $r.Bottom - $r.Top
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
[void][ShotCap2]::PrintWindow($script:found, $hdc, 2)
$g.ReleaseHdc($hdc)
$g.Dispose()
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "saved $Out ($w x $h)"
