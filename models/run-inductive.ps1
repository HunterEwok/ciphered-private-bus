# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Proof of a state machine model's safety (a folder under models/, named by
# -Model) with Apalache, from the inductive invariant in the model's
# inductive.qnt, on a shared machine with progress output. Works
# in Windows PowerShell 5.1 and PowerShell 7; needs Java 17 or later, Node, and
# git, but not Python.
#
# Three obligations: init implies IndInv, IndInv and one step imply IndInv, and
# IndInv implies safety. Apalache hands each check to one solver, which runs on
# one core. With -Split the second obligation is checked branch by branch of
# the step (the actions listed under "inductive.steps" in the model's
# checks.json, which together are exactly the step), and up to
# -Parallel checks run at the same time. Each check gets its own Apalache
# server at below-normal priority; together they use at most half of the
# -Share of the memory as Java heap (the solver needs memory outside the heap
# too). Everything is written under -WorkDir, with a summary at the end.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model channels `
#     -WorkDir D:\runs -Java C:\jdk\bin\java.exe -Split
#   ... -Model membership -Main large_ind -Split -Parallel 12
#
# -Main defaults to "inductive.instance" in checks.json.
#
# Exit status: 0 every obligation holds, 1 otherwise.

param(
    [Parameter(Mandatory = $true)][string]$Model,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$Java = "java",
    [string]$Main = "",
    [switch]$Split,
    [int]$Parallel = 0,
    [double]$Share = 0.85,
    [int]$Port = 8822,
    [int]$IntervalSeconds = 60,
    [int]$TimeoutHours = 0
)

$ErrorActionPreference = "Stop"
$ModelsDir = $PSScriptRoot
$ModelDir = Join-Path $ModelsDir $Model
if (-not (Test-Path (Join-Path $ModelDir "checks.json"))) { throw "No model $Model (models/$Model/checks.json)" }
$Checks = (Get-Content (Join-Path $ModelDir "checks.json") -Raw | ConvertFrom-Json).inductive
if (-not $Checks) { throw "models/$Model/checks.json has no inductive section" }
if (-not $Main) { $Main = $Checks.instance }
$OnWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'

function Say([string]$Text) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Text) }

function Get-ShortHash([string[]]$Names) {
    $bytes = @()
    foreach ($n in $Names) { $bytes += [System.IO.File]::ReadAllBytes((Join-Path $ModelDir $n)) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return (-join ($sha.ComputeHash([byte[]]$bytes) | ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
}

function Format-Span([TimeSpan]$T) { return "{0:%d}d {0:hh}:{0:mm}" -f $T }

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path

# Quint and Apalache use the java found on the PATH.
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

$modelHash = Get-ShortHash @("$Model.qnt", "instances.qnt")
$invHash = Get-ShortHash @("inductive.qnt")
$saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$commit = "$(& git -C $ModelDir rev-parse --short HEAD 2>$null)".Trim()
$ErrorActionPreference = $saved
$RunDir = Join-Path $WorkDir ("{0}-{1}-{2}" -f $Model, $Main, (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Say ("Model {5} {0}, inductive invariant {1}, commit {2}, instance {3}, Apalache {4}" -f $modelHash, $invHash, $commit, $Main, $apalache, $Model)
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
    try { & $quint verify "--main=$($Checks.smallInstance)" --init=modelInit --step=modelStep --invariant=IndInv --max-steps=0 "--apalache-version=$apalache" inductive.qnt 2>&1 | Out-Null }
    finally { $ErrorActionPreference = $saved; Pop-Location }
    $jar = Find-ApalacheJar
    if (-not $jar) { throw "apalache.jar $apalache not found under $($env:QUINT_HOME)" }
}

# The checks. Each is (name, init, step, invariant, steps).
$jobs = @(, @("init implies IndInv", "modelInit", "modelStep", "IndInv", 0))
if ($Split) {
    foreach ($s in $Checks.steps) {
        $jobs += , @(("IndInv and {0} imply IndInv" -f ($s -replace '^step', '')), "indInit", $s, "IndInv", 1)
    }
} else {
    $jobs += , @("IndInv and step imply IndInv", "indInit", "modelStep", "IndInv", 1)
}
$jobs += , @("IndInv implies safety", "indInit", "modelStep", "modelSafety", 0)

# Resources: every running check has its own server and heap.
if ($Parallel -le 0) { $Parallel = if ($Split) { 8 } else { 1 } }
$Parallel = [math]::Min($Parallel, $jobs.Count)
$cores = [Environment]::ProcessorCount
$Parallel = [math]::Max(1, [math]::Min($Parallel, [math]::Floor($cores * $Share)))
if ($OnWindows) { $memBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
else { $memBytes = [int64](((Get-Content /proc/meminfo | Where-Object { $_ -like "MemTotal:*" }) -split "\s+")[1]) * 1024 }
$memGb = [math]::Floor($memBytes / 1GB)
$heapGb = [math]::Max(2, [math]::Floor($memGb * $Share * 0.5 / $Parallel))
$compat = @()
$saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
& $Java --sun-misc-unsafe-memory-access=allow -version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { $compat = @("--sun-misc-unsafe-memory-access=allow") }
$ErrorActionPreference = $saved
Say ("{0} checks, {1} at a time, heap {2} GB each, {3} GB RAM, {4} cores" -f $jobs.Count, $Parallel, $heapGb, $memGb, $cores)

# Stopping never throws: a process that is already gone, or a child that
# Windows refuses to stop, must not end the run.
function Stop-Tree($Proc) {
    if (-not $Proc -or $Proc.HasExited) { return }
    $saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try {
        if ($OnWindows) { & taskkill /PID $Proc.Id /T /F 2>&1 | Out-Null }
        if (-not $Proc.HasExited) { Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue }
        $Proc.WaitForExit(10000) | Out-Null
    } catch { } finally { $ErrorActionPreference = $saved }
}

function Test-Port([int]$P) {
    try { $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect("127.0.0.1", $P); $tcp.Close(); return $true } catch { return $false }
}

# Every check gets a port of its own, counting up from -Port and skipping
# ports in use, so that a server still shutting down (or left over from an
# earlier run) never stops the run.
$script:NextPort = $Port
function Get-FreePort {
    for ($k = 0; $k -lt 1000; $k++) {
        $p = $script:NextPort; $script:NextPort++
        if (-not (Test-Port $p)) { return $p }
    }
    throw "No free port from $Port to $($script:NextPort); pass another -Port"
}

# Starts the server of a slot; the check itself starts once the port answers.
function Start-Check([int]$Index, [int]$Slot) {
    $j = $jobs[$Index]
    $p = Get-FreePort
    $tag = "{0:d2}-{1}" -f ($Index + 1), ($j[2] -replace '^step', '')
    $serverLog = Join-Path $RunDir "$tag-server.log"
    $sargs = $compat + @("-Xmx${heapGb}g", "-jar", "`"$($jar.FullName)`"", "server", "--port=$p")
    $server = Start-Process -FilePath $Java -ArgumentList $sargs -WorkingDirectory $RunDir -PassThru -NoNewWindow `
        -RedirectStandardOutput $serverLog -RedirectStandardError ($serverLog + ".err")
    try { $server.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
    return [pscustomobject]@{ Index = $Index; Slot = $Slot; Port = $p; Tag = $tag; Server = $server; ServerLog = $serverLog;
                              Quint = $null; Log = (Join-Path $RunDir "$tag.log"); Started = (Get-Date); Waited = 0 }
}

function Start-Quint($C) {
    $j = $jobs[$C.Index]
    $qargs = @("verify", "--main=$Main", "--init=$($j[1])", "--step=$($j[2])", "--invariant=$($j[3])",
               "--max-steps=$($j[4])", "--server-endpoint=localhost:$($C.Port)", "inductive.qnt")
    $exe = if ($OnWindows) { "cmd.exe" } else { $quint }
    $argList = if ($OnWindows) { @("/c", "`"$quint`"") + $qargs } else { $qargs }
    $C.Quint = Start-Process -FilePath $exe -ArgumentList $argList -WorkingDirectory $ModelDir -PassThru -NoNewWindow `
        -RedirectStandardOutput $C.Log -RedirectStandardError ($C.Log + ".err")
    try { $C.Quint.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
}

function Get-Verdict($C, [bool]$TimedOut) {
    if ($TimedOut) { return "stopped at the time limit" }
    $text = @()
    foreach ($f in @($C.Log, ($C.Log + ".err"))) { if (Test-Path $f) { $text += Get-Content $f } }
    if (($text -match '^\[ok\]').Count -gt 0) { return "holds" }
    # Apalache checks for deadlock: a branch that no state enables is reported
    # as one, which is not a counterexample to the invariant.
    if (($text -match 'deadlock').Count -gt 0) { return "DEADLOCK (no transition of this branch is enabled), see $($C.Log)" }
    if (($text -match '^\[violation\]').Count -gt 0) { return "VIOLATED, see $($C.Log)" }
    # No verdict: name the first error found, the server's first (it is
    # usually the cause, for example an OutOfMemoryError), then Quint's.
    # Running out of memory first, since the solver's log has other lines
    # that mention errors; Java's protobuf warning is not one.
    $cause = ""
    $files = @($C.ServerLog, ($C.ServerLog + ".err"), $C.Log, ($C.Log + ".err")) | Where-Object { Test-Path $_ }
    foreach ($pattern in @('OutOfMemory|Ran out of heap', 'Exception|[Ee]rror')) {
        foreach ($f in $files) {
            if ($cause) { break }
            $hit = Get-Content $f | Where-Object { $_ -match $pattern -and $_ -notmatch 'protobuf|gencode' } | Select-Object -First 1
            if ($hit) { $cause = ": " + $hit.Trim().Substring(0, [math]::Min(160, $hit.Trim().Length)) }
        }
    }
    return "no verdict$cause; see $($C.Log) and $($C.ServerLog)"
}

$results = @{}
$running = @()
$next = 0
$freeSlots = New-Object System.Collections.Generic.Queue[int]
for ($s = 0; $s -lt $Parallel; $s++) { $freeSlots.Enqueue($s) }
$startedAll = Get-Date
$lastReport = Get-Date
try {
    while ($next -lt $jobs.Count -or $running.Count -gt 0) {
        while ($next -lt $jobs.Count -and $freeSlots.Count -gt 0) {
            $c = Start-Check $next $freeSlots.Dequeue()
            Say ("Started {0}" -f $jobs[$next][0])
            $running += $c
            $next++
        }
        Start-Sleep -Seconds 1
        $still = @()
        foreach ($c in $running) {
            $done = $false; $timedOut = $false
            if (-not $c.Quint) {
                if (Test-Port $c.Port) { Start-Quint $c }
                elseif ($c.Server.HasExited -or ((Get-Date) - $c.Started).TotalSeconds -gt 180) {
                    $results[$c.Index] = "server did not start, see $($c.ServerLog)"; $done = $true
                }
            } elseif ($c.Quint.HasExited) {
                $results[$c.Index] = Get-Verdict $c $false; $done = $true
            } elseif ($TimeoutHours -gt 0 -and ((Get-Date) - $c.Started).TotalHours -ge $TimeoutHours) {
                Stop-Tree $c.Quint
                $results[$c.Index] = Get-Verdict $c $true; $done = $true
            }
            if ($done) {
                Stop-Tree $c.Server
                $mins = ((Get-Date) - $c.Started).TotalMinutes
                Say ("{0}: {1} ({2:N1} min)" -f $jobs[$c.Index][0], $results[$c.Index], $mins)
                $results[$c.Index] = "{0}|{1:N1}" -f $results[$c.Index], $mins
                $freeSlots.Enqueue($c.Slot)
            } else { $still += $c }
        }
        $running = $still
        if (((Get-Date) - $lastReport).TotalSeconds -ge $IntervalSeconds -and $running.Count -gt 0) {
            $lastReport = Get-Date
            Say ("{0} elapsed | done {1} of {2} | running: {3}" -f (Format-Span ((Get-Date) - $startedAll)), $results.Count,
                $jobs.Count, (($running | ForEach-Object { "{0} {1}" -f ($_.Tag -replace '^\d+-', ''), (Format-Span ((Get-Date) - $_.Started)) }) -join ", "))
        }
    }
} finally {
    foreach ($c in $running) { Stop-Tree $c.Quint; Stop-Tree $c.Server }
}

$rows = @(); $failures = 0
for ($i = 0; $i -lt $jobs.Count; $i++) {
    $verdict, $mins = $results[$i] -split '\|'
    if ($verdict -ne "holds") { $failures++ }
    $rows += ("{0,-4}  {1,-44} {2}  {3,8} min" -f $(if ($verdict -eq "holds") { "pass" } else { "FAIL" }), $jobs[$i][0], $verdict, $mins)
}
$summary = @(
    "model: $Model",
    "model hash: $modelHash",
    "inductive invariant hash: $invHash",
    "commit: $commit",
    "instance: $Main$(if ($Split) { ', step split into its branches' })",
    "apalache: $apalache, $Parallel at a time, heap $heapGb GB each",
    "started: $($startedAll.ToString('u')), ended: $((Get-Date).ToString('u')), elapsed: $((Get-Date) - $startedAll)",
    ""
) + $rows + @("", $(if ($failures -eq 0) { "result: safety holds in every reachable state" } else { "result: not proved" }))
[System.IO.File]::WriteAllLines((Join-Path $RunDir "summary.txt"), $summary)
Say "Summary ($(Join-Path $RunDir 'summary.txt')):"
$summary | ForEach-Object { Write-Host "  $_" }
if ($failures -eq 0) { exit 0 } else { exit 1 }
