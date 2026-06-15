<#
Starts (or stops) the HEADLESS Ghidra MCP server — no Ghidra GUI required.
Runs nrs.exe from the existing project under analyzeHeadless with
GhidraMCPHeadless.java, which serves the MCP HTTP API on 127.0.0.1:8080.
The .mcp.json bridge proxies Claude's mcp__ghidra__* tools to this server.

  Start:  powershell -File tools\ghidra_mcp\start_headless.ps1
  Stop:   powershell -File tools\ghidra_mcp\start_headless.ps1 -Stop
#>
param([switch]$Stop)

$repo    = Split-Path (Split-Path $PSScriptRoot)   # tools/ghidra_mcp -> repo root
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
        # analyzeHeadless spawns a child java; kill any java serving 8080 too
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
# -preScript ApplyKnownNames applies data/known_names.json (RVA->name) into the live program
# before the (blocking) MCP server postScript starts, so mcp__ghidra__* shows our names.
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
