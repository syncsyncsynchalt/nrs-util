<#
HEADLESS な Ghidra MCP サーバを起動（または停止）する。Ghidra GUI は不要。
既存プロジェクトの nrs.exe を analyzeHeadless 上で GhidraMCPHeadless.java とともに動かし、
127.0.0.1:8080 で MCP HTTP API を提供する。
.mcp.json の bridge が Claude の mcp__ghidra__* tool をこのサーバへ中継する。

  Start:  powershell -File tools\ghidra_mcp\start_headless.ps1
  Stop:   powershell -File tools\ghidra_mcp\start_headless.ps1 -Stop
#>
param([switch]$Stop)

$repo    = Split-Path (Split-Path $PSScriptRoot)   # tools/ghidra_mcp -> リポジトリルート
$ghidra  = "C:\Tools\ghidra_12.1.2_PUBLIC"
$proj    = Join-Path $repo "data\ghidra_nrs"
$projName= "nrs"
$program = "nrs.exe"
$scripts = Join-Path $repo "tools\ghidra_mcp\ghidra_scripts"
$log     = Join-Path $repo "captures\ghidra_headless.log"
$pidFile = Join-Path $repo "captures\ghidra_headless.pid"

if ($Stop) {
    if (Test-Path $pidFile) {
        $procId = Get-Content $pidFile
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        # analyzeHeadless は子プロセスの java を起こす。8080 を提供している java も停止させる
        Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
        Remove-Item $pidFile -ErrorAction SilentlyContinue
        Write-Host "stopped headless Ghidra MCP server"
    } else { Write-Host "no pid file; nothing to stop" }
    return
}

if (Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "port 8080 already serving — server appears to be running"; return
}

New-Item -ItemType Directory -Force (Join-Path $repo "captures") | Out-Null
# -preScript ApplyKnownNames は data/known_names.json (static_VA->名) を、ブロックする MCP サーバの
# postScript が起動する前に live program へ適用する。これで mcp__ghidra__* に我々の名前が表示される。
$args = @($proj, $projName, "-process", $program, "-noanalysis",
          "-scriptPath", $scripts,
          "-preScript", "ApplyKnownNames.java",
          "-postScript", "GhidraMCPHeadless.java")
$p = Start-Process "$ghidra\support\analyzeHeadless.bat" -ArgumentList $args `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden -PassThru
$p.Id | Set-Content $pidFile
Write-Host "headless Ghidra MCP server starting (PID $($p.Id))."
Write-Host "ready when 'HTTP server listening on port 8080' appears in:"
Write-Host "  $log"
