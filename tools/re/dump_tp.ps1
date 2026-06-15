# dump_tp.ps1: pe-sieve で TeknoParrot.dll を nrs.exe プロセスメモリからダンプする
#
# 用途: VMProtect でパックされた TeknoParrot.dll のアンパック後コードを取得し Ghidra で解析する。
#   仮想化コード (teknoGod セクション) は依然 VM バイトコードのまま読めないが、
#   ミューテーションコードと InitKonami/InitLinux/InitializeASI エクスポートは解析可能。
#
# 前提: TeknoParrot で nrs.exe が起動済みであること
#
# 使い方:
#   powershell -File tools\dump_tp.ps1           # nrs.exe PID を自動検出
#   powershell -File tools\dump_tp.ps1 -Pid 1234 # PID 直指定
#
# pe-sieve32.exe が tools\ になければ取得方法を案内する。

param([int]$Pid = 0)

$ErrorActionPreference = "Stop"

$toolsDir  = Split-Path $PSCommandPath -Parent
$peSieve   = Join-Path $toolsDir "pe-sieve32.exe"
$captureDir = Join-Path $toolsDir "..\captures\pe_dump"
$captureDir = [System.IO.Path]::GetFullPath($captureDir)

# ─── pe-sieve32.exe チェック ────────────────────────────────────────────────
if (-not (Test-Path $peSieve)) {
    Write-Host "[!] pe-sieve32.exe が見つかりません: $peSieve" -ForegroundColor Red
    Write-Host ""
    Write-Host "取得方法 (どちらでも可):"
    Write-Host ""
    Write-Host "  方法 A — PowerShell で直接ダウンロード:"
    Write-Host '    $url = "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe_sieve32.zip"'
    Write-Host "    Invoke-WebRequest `$url -OutFile `"$env:TEMP\pe_sieve32.zip`""
    Write-Host "    Expand-Archive `"$env:TEMP\pe_sieve32.zip`" -DestinationPath `"$toolsDir`""
    Write-Host "    # → $toolsDir\pe-sieve32.exe が配置される"
    Write-Host ""
    Write-Host "  方法 B — ブラウザから手動:"
    Write-Host "    https://github.com/hasherezade/pe-sieve/releases"
    Write-Host "    pe_sieve32.zip をダウンロード → pe-sieve32.exe を $toolsDir に配置"
    Write-Host ""
    exit 1
}

# ─── nrs.exe PID 検出 ─────────────────────────────────────────────────────
if ($Pid -eq 0) {
    $proc = Get-Process -Name "nrs" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        Write-Host "[!] nrs.exe が見つかりません。TeknoParrot で nrs.exe を起動してから実行してください。" -ForegroundColor Red
        exit 1
    }
    $Pid = $proc.Id
    Write-Host "[*] nrs.exe PID=$Pid 検出" -ForegroundColor Cyan
}

# ─── ダンプ実行 ──────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $captureDir | Out-Null

Write-Host "[*] pe-sieve32.exe オプション:"
Write-Host "    /pid $Pid  — 対象プロセス"
Write-Host "    /imp 1     — IAT 再構築 (実行時解決した API を修復)"
Write-Host "    /dir $captureDir"
Write-Host ""

& $peSieve /pid $Pid /imp 1 /dir $captureDir

Write-Host ""
Write-Host "[*] ダンプ完了。出力先: $captureDir" -ForegroundColor Green
Write-Host ""
Write-Host "次のステップ:"
Write-Host "  1. $captureDir\TeknoParrot_${Pid}_dump.dll を Ghidra にインポート"
Write-Host "  2. VirtualProtect ログ (jvsstate-tp-*.txt の VP_EXEC 行) の RVA を先に逆コンパイル"
Write-Host "     例: mcp__ghidra__decompile_function_by_address (ダンプの static VA = ダンプ base + RVA)"
Write-Host "  3. エクスポート: InitKonami / InitLinux / InitializeASI を逆コンパイル"
Write-Host "     (VMProtect VM ハンドラの外側にある初期化ロジックが見える可能性あり)"
Write-Host "  4. GP_WRITE→VP_EXEC ペアで判明した nrs.exe パッチ RVA と FACTS.md を照合し"
Write-Host "     nrs-util に未実装のパッチを特定 → frida/diag/ に patchCode を追加"
