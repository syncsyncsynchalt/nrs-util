<#
HEADLESS な Ghidra MCP サーバを起動（または停止）する。Ghidra GUI は不要。
既存プロジェクトの nrs.exe を analyzeHeadless 上で GhidraMCPHeadless.java とともに動かし、
8080 で MCP HTTP API を提供する。.mcp.json の bridge が mcp__ghidra__* をこのサーバへ中継する。

  Start:  powershell -File tools\ghidra_mcp\start_headless.ps1
  Stop:   powershell -File tools\ghidra_mcp\start_headless.ps1 -Stop

Start は 8080 が応答するまでポーリングし、成功で exit 0 / タイムアウト・早期終了で exit 1。
Stop は graceful: sentinel ファイルでサーバループを抜けさせ、analyzeHeadless の「終了時保存」に
到達させる（= MCP の rename/型/コメントが DB に永続）。数秒で終わらなければ force-kill にフォールバック。
Ghidra の場所は $env:GHIDRA_INSTALL_DIR を優先（無ければ既定パス）。
#>
param([switch]$Stop)

$repo     = Split-Path (Split-Path $PSScriptRoot)   # tools/ghidra_mcp -> リポジトリルート
$ghidra   = if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Tools\ghidra_12.1.2_PUBLIC" }
$headless = Join-Path $ghidra "support\analyzeHeadless.bat"
$proj     = Join-Path $repo "data\ghidra_nrs"
$projName = "nrs"
$program  = "nrs.exe"
$scripts  = Join-Path $repo "tools\ghidra_mcp\ghidra_scripts"
$log      = Join-Path $repo "captures\ghidra_headless.log"
$pidFile  = Join-Path $repo "captures\ghidra_headless.pid"
$sentinel = Join-Path $repo "captures\ghidra_shutdown.request"

# 8080 を LISTEN しているプロセス（= 実 java サーバ）の PID。無ければ $null。
function Get-Port8080Pid {
    $c = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $c.OwningProcess } else { $null }
}

if ($Stop) {
    if (-not (Get-Port8080Pid) -and -not (Test-Path $pidFile)) { Write-Host "not running; nothing to stop"; exit 0 }
    # graceful: サーバループに終了を要求 -> run() が return -> analyzeHeadless が program を保存
    New-Item -ItemType Directory -Force (Split-Path $sentinel) | Out-Null
    Set-Content -Path $sentinel -Value "stop" -Encoding ascii
    Write-Host "graceful shutdown requested; waiting for save-on-exit..."
    $stopped = $false
    for ($i = 0; $i -lt 60; $i++) {          # 最大 ~30s
        Start-Sleep -Milliseconds 500
        if (-not (Get-Port8080Pid)) { $stopped = $true; break }
    }
    if ($stopped) {
        Write-Host "stopped gracefully (program saved on exit)"
    } else {
        Write-Host "graceful stop timed out; force-killing (session work may be lost)"
        $owner = Get-Port8080Pid
        if ($owner) { Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item $pidFile  -ErrorAction SilentlyContinue
    Remove-Item $sentinel -ErrorAction SilentlyContinue
    exit 0
}

# ---- Start ----
if (Get-Port8080Pid) { Write-Host "port 8080 already serving — server appears to be running"; exit 0 }
if (-not (Test-Path $headless)) {
    Write-Error "analyzeHeadless not found: $headless  ( set `$env:GHIDRA_INSTALL_DIR )"; exit 1
}
New-Item -ItemType Directory -Force (Join-Path $repo "captures") | Out-Null
Remove-Item $sentinel -ErrorAction SilentlyContinue      # 前回の残骸を除去

# 名前/型/コメントは DB に永続化されるため preScript 再適用は不要（旧 ApplyKnownNames は撤去）。
$argList = @($proj, $projName, "-process", $program, "-noanalysis",
             "-scriptPath", $scripts,
             "-postScript", "GhidraMCPHeadless.java")
$p = Start-Process $headless -ArgumentList $argList `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden -PassThru
Write-Host "headless Ghidra MCP server starting (launcher PID $($p.Id)); waiting for readiness..."

# readiness ポーリング（最大 ~120s）。cmd ラッパーではなく 8080 を所有する java の PID を記録する。
$ready = $false
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Seconds 1
    $owner = Get-Port8080Pid
    if ($owner) {
        Set-Content -Path $pidFile -Value $owner -Encoding ascii
        Write-Host "READY: MCP serving on 8080 (java PID $owner)"
        $ready = $true; break
    }
    if ($p.HasExited) { Write-Error "launcher exited before serving (code $($p.ExitCode)). See $log / $log.err"; exit 1 }
}
if (-not $ready) { Write-Error "TIMEOUT: 8080 not serving after ~120s. See $log"; exit 1 }
exit 0
