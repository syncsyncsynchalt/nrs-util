# touch_test.ps1 - screenshot-driven test harness for nrs.exe (WGL window).
# ASCII-only (PowerShell 5.1 misreads UTF-8 BOM-less files as CP932 and fails to parse).
#
# Capture uses the in-process GL frame capture (src/host/capture.c). External window-find +
# CopyFromScreen was unreliable (occlusion, GL backbuffer not captured, Get-Process flaky).
#   shot:  drop capture.req in cwd (C:\src\bbs) -> host saves next frame to capture.png -> copy here.
#   touch/coin/info: find window by title 'WGL' (FindWindow, no Get-Process dependency).
#     touch_sample_mouse reads GetForegroundWindow client rect, so foreground WGL before input
#     and give client-fraction (0..1) position.
#
# Usage (one action per call):
#   touch_test.ps1 -Action shot  -Out shot.png
#   touch_test.ps1 -Action coin  -N 5
#   touch_test.ps1 -Action touch -X 0.9 -Y 0.12 -HoldMs 800   # client fraction (top-right = high X, low Y)
#   touch_test.ps1 -Action info
param(
  [Parameter(Mandatory=$true)][ValidateSet('shot','coin','touch','info')] [string]$Action,
  [string]$Out,
  [int]$N = 1,
  [double]$X = 0.5,
  [double]$Y = 0.5,
  [int]$HoldMs = 700,
  [int]$Vk = 0x35,
  [string]$Title = 'WGL',
  [string]$BbsDir = 'C:\src\bbs'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class TT {
 public delegate bool Cb(IntPtr h,IntPtr p);
 [DllImport("user32.dll")] public static extern bool EnumWindows(Cb c,IntPtr p);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int c);
 [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h,out R r);
 [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h,ref P p);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,IntPtr e);
 [DllImport("user32.dll")] public static extern void keybd_event(byte v,byte s,uint f,IntPtr e);
 static IntPtr found; static string want;
 static bool Each(IntPtr h,IntPtr l){ StringBuilder s=new StringBuilder(256);
   GetWindowText(h,s,256); if(s.ToString()==want) found=h; return true; }
 public static IntPtr FindByTitle(string t){ want=t; found=IntPtr.Zero; EnumWindows(Each,IntPtr.Zero); return found; }
 [StructLayout(LayoutKind.Sequential)] public struct R{public int L,T,Ri,B;}
 [StructLayout(LayoutKind.Sequential)] public struct P{public int X,Y;} }
"@

function Get-Wgl {
  for ($i=0; $i -lt 25; $i++) {
    $h = [TT]::FindByTitle($Title)
    if ($h -ne [IntPtr]::Zero) { return $h }
    Start-Sleep -Milliseconds 200
  }
  return [IntPtr]::Zero
}

switch ($Action) {
 'shot' {
   if (-not $Out) { Write-Output "ERROR: -Out required"; exit 1 }
   $png = Join-Path $BbsDir 'capture.png'
   $req = Join-Path $BbsDir 'capture.req'
   if (Test-Path $png) { Remove-Item $png -Force }
   New-Item -ItemType File -Path $req -Force | Out-Null
   $deadline = (Get-Date).AddSeconds(6); $ok = $false
   while ((Get-Date) -lt $deadline) {
     if (Test-Path $png) { Start-Sleep -Milliseconds 150; $ok = $true; break }
     Start-Sleep -Milliseconds 120
   }
   if (-not $ok) { Write-Output "ERROR: capture.png not produced (capture hook running?)"; exit 1 }
   Copy-Item $png $Out -Force
   Write-Output ("shot saved -> {0} ({1} bytes)" -f $Out,(Get-Item $Out).Length)
 }
 'info' {
   $h = Get-Wgl
   if ($h -eq [IntPtr]::Zero) { Write-Output "ERROR: window '$Title' not found"; exit 1 }
   $c = New-Object TT+R; [void][TT]::GetClientRect($h,[ref]$c)
   Write-Output ("hwnd={0} client={1}x{2}" -f $h,$c.Ri,$c.B)
 }
 'coin' {
   $h = Get-Wgl
   if ($h -eq [IntPtr]::Zero) { Write-Output "ERROR: window '$Title' not found"; exit 1 }
   [TT]::ShowWindow($h,5)|Out-Null; [TT]::SetForegroundWindow($h)|Out-Null; Start-Sleep -Milliseconds 250
   for($i=0;$i -lt $N;$i++){ [TT]::keybd_event([byte]$Vk,0,0,[IntPtr]::Zero); Start-Sleep -Milliseconds 130
     [TT]::keybd_event([byte]$Vk,0,2,[IntPtr]::Zero); Start-Sleep -Milliseconds 300 }
   Write-Output "coin x$N (vk=$Vk) sent"
 }
 'touch' {
   $h = Get-Wgl
   if ($h -eq [IntPtr]::Zero) { Write-Output "ERROR: window '$Title' not found"; exit 1 }
   [TT]::ShowWindow($h,5)|Out-Null; [TT]::SetForegroundWindow($h)|Out-Null; Start-Sleep -Milliseconds 250
   $c = New-Object TT+R; [void][TT]::GetClientRect($h,[ref]$c)
   $cx = [int][math]::Round($c.Ri*$X); $cy = [int][math]::Round($c.B*$Y)
   $p = New-Object TT+P; $p.X=$cx; $p.Y=$cy; [void][TT]::ClientToScreen($h,[ref]$p)
   [TT]::SetCursorPos($p.X,$p.Y)|Out-Null; Start-Sleep -Milliseconds 150
   [TT]::mouse_event(0x02,0,0,0,[IntPtr]::Zero)
   Start-Sleep -Milliseconds $HoldMs
   [TT]::mouse_event(0x04,0,0,0,[IntPtr]::Zero)
   Write-Output ("touch client=({0},{1}) screen=({2},{3}) hold={4}ms" -f $cx,$cy,$p.X,$p.Y,$HoldMs)
 }
}
