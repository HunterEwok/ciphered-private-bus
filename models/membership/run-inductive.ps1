# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Proof of the membership model's safety with Apalache, from the inductive
# invariant in inductive.qnt, on a shared machine with progress output. Works
# in Windows PowerShell 5.1 and PowerShell 7; needs Java 17 or later, Node, and
# git, but not Python.
#
# It checks the three obligations one after another: init implies IndInv,
# IndInv and one step imply IndInv, and IndInv implies safety. The script starts
# its own Apalache server at below-normal priority with a Java heap of half of
# the -Share of the memory (the solver needs memory outside the heap too), and
# stops it at the end. Everything is written under -WorkDir, and a summary is
# written at the end.
#
# Example:
#   powershell -ExecutionPolicy Bypass -File models\membership\run-inductive.ps1 `
#     -WorkDir D:\runs -Java C:\jdk\bin\java.exe -Main large_ind
#
# Exit status: 0 every obligation holds, 1 otherwise.

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$Java = "java",
    [string]$Main = "large_ind",
    [double]$Share = 0.85,
    [int]$Port = 8822,
    [int]$IntervalSeconds = 60,
    [int]$TimeoutHours = 0
)

$ErrorActionPreference = "Stop"
$ModelDir = $PSScriptRoot
$ModelsDir = Split-Path -Parent $ModelDir
$OnWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'

function Say([string]$Text) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Text) }

function Get-ShortHash([string[]]$Names) {
    $bytes = @()
    foreach ($n in $Names) { $bytes += [System.IO.File]::ReadAllBytes((Join-Path $ModelDir $n)) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return (-join ($sha.ComputeHash([byte[]]$bytes) | ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path

# Quint starts Apalache with the java found on the PATH.
if ($Java -ne "java") {
    $Java = (Resolve-Path $Java).Path
    $javaBin = Split-Path -Parent $Java
    $env:JAVA_HOME = Split-Path -Parent $javaBin
    $env:PATH = $javaBin + [System.IO.Path]::PathSeparator + $env:PATH
}
$env:QUINT_HOME = Join-Path $WorkDir "quint-home"
$env:npm_config_cache = Join-Path $WorkDir "npm-cache"

$quint = Join-Path $ModelsDir ("node_modules/.bin/" + $(if ($OnWindows) { "quint.cmd" } else { "quint" }))
if (-not (Test-Path $quint)) {
    Say "Installing Quint from models/package-lock.json"
    Push-Location $ModelsDir
    try { & npm ci --ignore-scripts | Out-Host } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
}

$versions = Get-Content (Join-Path (Split-Path -Parent $ModelsDir) "tools/versions/versions.toml") -Raw
if ($versions -notmatch '(?ms)^\[apalache\].*?^version\s*=\s*"([^"]+)"') { throw "No Apalache version in tools/versions/versions.toml" }
$apalache = $Matches[1]

$modelHash = Get-ShortHash @("membership.qnt", "instances.qnt")
$invHash = Get-ShortHash @("inductive.qnt")
$saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$commit = "$(& git -C $ModelDir rev-parse --short HEAD 2>$null)".Trim()
$ErrorActionPreference = $saved
$RunDir = Join-Path $WorkDir ("{0}-{1}" -f $Main, (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Say ("Model {0}, inductive invariant {1}, commit {2}, instance {3}, Apalache {4}" -f $modelHash, $invHash, $commit, $Main, $apalache)
Say "Run folder $RunDir"

# Apalache itself: Quint downloads it on first use. A cheap check of the small
# instance triggers the download if it is missing.
function Find-ApalacheJar { Get-ChildItem -Path $env:QUINT_HOME -Recurse -Filter "apalache.jar" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "*apalache-dist-$apalache*" } | Select-Object -First 1 }
$jar = Find-ApalacheJar
if (-not $jar) {
    Say "Downloading Apalache $apalache"
    Push-Location $ModelDir
    $saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & $quint verify --main=tiny_ind --init=modelInit --step=modelStep --invariant=IndInv --max-steps=0 "--apalache-version=$apalache" inductive.qnt 2>&1 | Out-Null }
    finally { $ErrorActionPreference = $saved; Pop-Location }
    $jar = Find-ApalacheJar
    if (-not $jar) { throw "apalache.jar $apalache not found under $($env:QUINT_HOME)" }
}

# The server, with a heap that fits the share of the machine. Quint's own
# launcher on Windows always uses 4 GB, which is too little for three devices.
if ($OnWindows) { $memBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
else { $memBytes = [int64](((Get-Content /proc/meminfo | Where-Object { $_ -like "MemTotal:*" }) -split "\s+")[1]) * 1024 }
$memGb = [math]::Floor($memBytes / 1GB)
$heapGb = [math]::Max(2, [math]::Floor($memGb * $Share * 0.5))
$serverArgs = @()
$saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
& $Java --sun-misc-unsafe-memory-access=allow -version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { $serverArgs += "--sun-misc-unsafe-memory-access=allow" }
$ErrorActionPreference = $saved
$serverArgs += @("-Xmx${heapGb}g", "-jar", "`"$($jar.FullName)`"", "server", "--port=$Port")
$serverLog = Join-Path $RunDir "apalache-server.log"
$server = Start-Process -FilePath $Java -ArgumentList $serverArgs -WorkingDirectory $RunDir -PassThru -NoNewWindow `
    -RedirectStandardOutput $serverLog -RedirectStandardError ($serverLog + ".err")
try { $server.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { Say "Could not lower the priority: $_" }
Say ("Apalache server PID {0}, port {1}, heap {2} GB of {3} GB RAM" -f $server.Id, $Port, $heapGb, $memGb)
$ready = $false
for ($k = 0; $k -lt 120 -and -not $ready -and -not $server.HasExited; $k++) {
    Start-Sleep -Seconds 1
    try { $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect("127.0.0.1", $Port); $tcp.Close(); $ready = $true } catch { }
}
if (-not $ready) {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    throw "The Apalache server did not start; see $serverLog (is port $Port in use? pass -Port)"
}

$checks = @(
    @("init implies IndInv", "modelInit", "IndInv", 0),
    @("IndInv and step imply IndInv", "indInit", "IndInv", 1),
    @("IndInv implies safety", "indInit", "modelSafety", 0)
)
$rows = @(); $failures = 0; $startedAll = Get-Date
$progress = '(Step \d+:.*|State \d+:.*|The outcome is:.*)\s+[IWE]@'
for ($i = 0; $i -lt $checks.Count; $i++) {
    $name, $init, $inv, $steps = $checks[$i]
    $log = Join-Path $RunDir ("{0}-{1}.log" -f ($i + 1), $inv)
    Say ("Obligation {0} of 3: {1}" -f ($i + 1), $name)
    $qargs = @("verify", "--main=$Main", "--init=$init", "--step=modelStep", "--invariant=$inv",
               "--max-steps=$steps", "--server-endpoint=localhost:$Port", "inductive.qnt")
    $exe = if ($OnWindows) { "cmd.exe" } else { $quint }
    $argList = if ($OnWindows) { @("/c", "`"$quint`"") + $qargs } else { $qargs }
    $t0 = Get-Date
    $p = Start-Process -FilePath $exe -ArgumentList $argList -WorkingDirectory $ModelDir -PassThru -NoNewWindow `
        -RedirectStandardOutput $log -RedirectStandardError ($log + ".err")
    try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { Say "Could not lower the priority: $_" }
    $timedOut = $false
    while (-not $p.HasExited) {
        $until = (Get-Date).AddSeconds($IntervalSeconds)
        while (-not $p.HasExited -and (Get-Date) -lt $until) { Start-Sleep -Seconds 1 }
        if ($p.HasExited) { break }
        $elapsed = (Get-Date) - $t0
        $last = $null
        foreach ($f in @($log, ($log + ".err"), $serverLog, ($serverLog + ".err"))) {
            if (Test-Path $f) {
                $m = Get-Content $f -Tail 200 | Where-Object { $_ -match $progress } | Select-Object -Last 1
                if ($m) { $last = ($m -replace '\s+[IWE]@\S+$', '') }
            }
        }
        Say ("  {0:%d}d {0:hh}:{0:mm} elapsed | {1}" -f $elapsed, $(if ($last) { $last } else { "preparing" }))
        if ($TimeoutHours -gt 0 -and $elapsed.TotalHours -ge $TimeoutHours) {
            Say "  Time limit of $TimeoutHours h reached: stopping. This is not a result."
            & taskkill /PID $p.Id /T /F | Out-Null
            $timedOut = $true
            break
        }
    }
    $p.WaitForExit()
    $text = @()
    foreach ($f in @($log, ($log + ".err"))) { if (Test-Path $f) { $text += Get-Content $f } }
    $got = if ($timedOut) { "stopped at the time limit" }
           elseif (($text -match '^\[ok\]').Count -gt 0) { "holds" }
           elseif (($text -match '^\[violation\]').Count -gt 0) { "VIOLATED, see $log" }
           else { "no verdict, see $log" }
    if ($got -ne "holds") { $failures++ }
    $mins = ((Get-Date) - $t0).TotalMinutes
    $rows += ("{0,-4}  {1,-30} {2}  {3,8:N1} min" -f $(if ($got -eq "holds") { "pass" } else { "FAIL" }), $name, $got, $mins)
    Say ("  {0}: {1} ({2:N1} min)" -f $name, $got, $mins)
}

if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }

$summary = @(
    "model hash: $modelHash",
    "inductive invariant hash: $invHash",
    "commit: $commit",
    "instance: $Main",
    "apalache: $apalache, heap $heapGb GB",
    "started: $($startedAll.ToString('u')), ended: $((Get-Date).ToString('u')), elapsed: $((Get-Date) - $startedAll)",
    ""
) + $rows + @("", $(if ($failures -eq 0) { "result: safety holds in every reachable state" } else { "result: not proved" }))
[System.IO.File]::WriteAllLines((Join-Path $RunDir "summary.txt"), $summary)
Say "Summary ($(Join-Path $RunDir 'summary.txt')):"
$summary | ForEach-Object { Write-Host "  $_" }
if ($failures -eq 0) { exit 0 } else { exit 1 }
