# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Exhaustive TLC run of a state machine model (a folder under models/, named
# by -Model) on a shared machine, with progress output. Works in Windows
# PowerShell 5.1 and PowerShell 7.
#
# It compiles an instance of the model's instances.qnt to TLA+, starts TLC at below-normal
# priority within a share of the CPU cores and memory, prints progress every
# interval, stops TLC if free disk space falls below a limit, and writes a
# summary at the end. Everything is written under -WorkDir.
#
# Example:
#   powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model channels `
#     -WorkDir D:\runs -Java C:\jdk\bin\java.exe
#
# Ctrl+C stops only the progress output; TLC keeps running. To stop TLC, use
# Stop-Process with the PID the script prints. To continue a stopped run from
# its last checkpoint, pass -Recover with the checkpoint folder (states\<date>).
# A run that ends with a verdict deletes its checkpoint and temporary files;
# the log and the summary stay.
# TLC writes a checkpoint every -CheckpointMinutes (default 60); 0 writes none,
# which saves disk space and time, but a stopped run then starts over.
# The state queue on disk is compressed (-gzip): about a sixth of the space
# at the same speed.
#
# -Probes checks the translation to TLA+ instead: it runs TLC on every probe
# instance (each must violate `safety`) and on every witness (each must be
# violated), as listed in the model's checks.json, one after another with -TimeoutMinutes each, and prints a table of
# expected and actual outcomes. A run that reaches its time limit has no
# verdict and counts as a failure.
#
# -View runs the instance and state view named under "view" in checks.json
# (file, instance, operator) with the TLC option VIEW: TLC keeps one state per
# value of the view. The view is proven exact for `safety` on its own instance
# only (models/<model>/view.qnt, section "bisim" of run-inductive.ps1), so
# -View refuses -Probes, -Temporal, another -Invariant and another -Main. The
# summary records the hash of the view's file next to the model hash.
#
# -Fp picks TLC's fingerprint function (0 to 130); without it TLC picks one at
# random. The summary records the one used. An exhaustive run can miss a state
# only if two distinct states share a fingerprint; a second run with another
# function makes the same miss need a collision in both runs.
#
# Exit status: 0 no error found (with -Probes: every outcome as expected),
# 2 invariant violated, 3 no verdict (time limit, disk limit, or an error).

param(
    [Parameter(Mandatory = $true)][string]$Model,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$Java = "java",
    [string]$Main = "",
    [string]$Invariant = "safety",
    [string]$Temporal = "",
    [double]$Share = 0.85,
    [int]$MinFreeDiskPercent = 15,
    [int]$IntervalSeconds = 60,
    [string]$Recover = "",
    [int]$CheckpointMinutes = 60,
    [int]$TimeoutMinutes = 0,
    [switch]$Probes,
    [switch]$View,
    [int]$Fp = -1
)

$ErrorActionPreference = "Stop"
$TlaToolsVersion = "1.7.4"
$TlaToolsUrl = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
$ApalacheModules = @("Apalache.tla", "Variants.tla", "Option.tla", "__apalache_folds.tla", "__apalache_internal.tla")

$ModelsDir = $PSScriptRoot
$ModelDir = Join-Path $ModelsDir $Model
if (-not (Test-Path (Join-Path $ModelDir "checks.json"))) { throw "No model $Model (models/$Model/checks.json)" }
$Checks = Get-Content (Join-Path $ModelDir "checks.json") -Raw | ConvertFrom-Json
$SourceFile = "instances.qnt"
if ($View) {
    if (-not $Checks.view) { throw "models/$Model/checks.json has no view" }
    if ($Probes -or $Temporal -or $Invariant -ne "safety") { throw "-View is proven for safety only: no -Probes, -Temporal or -Invariant" }
    if ($Main -and $Main -ne $Checks.view.instance) { throw "-View is proven for the instance $($Checks.view.instance) only, not $Main" }
    $SourceFile = $Checks.view.file
    if (-not $Main) { $Main = $Checks.view.instance }
}
if (-not $Main) { $Main = $Checks.tlcInstance }
$OnWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'

function Say([string]$Text) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Text) }

function Get-TotalMemoryBytes {
    if ($OnWindows) { return [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
    $line = (Get-Content /proc/meminfo | Where-Object { $_ -like "MemTotal:*" })
    return [int64](($line -split "\s+")[1]) * 1024
}

function Get-FreeDiskPercent([string]$Path) {
    $drive = New-Object System.IO.DriveInfo ([System.IO.Path]::GetPathRoot((Resolve-Path $Path).Path))
    return [math]::Round(100.0 * $drive.AvailableFreeSpace / $drive.TotalSize, 1)
}

function Get-ModelHash {
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $ModelDir "$Model.qnt")) +
             [System.IO.File]::ReadAllBytes((Join-Path $ModelDir "instances.qnt"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    return $hex.Substring(0, 12)
}

function Format-Count([int64]$N) { return $N.ToString("N0", [System.Globalization.CultureInfo]::InvariantCulture) }

# Runs a native command and returns its standard output lines. Standard error
# is collected separately: Windows PowerShell 5.1 would otherwise turn any
# line on it into a terminating error.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $script:NativeErrors = @()
    try {
        $out = & $Exe @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $script:NativeErrors += $_.ToString() } else { "$_" }
        }
        $script:NativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    return $out
}

# ------------------------------------------------------------------ probes mode
if ($Probes) {
    # Liveness probes need -Temporal and a long run, so checks.json leaves them out.
    $runs = @($Checks.probes | ForEach-Object { , @("probe_$_", "safety") }) +
            @($Checks.witnesses | ForEach-Object { , @($Checks.witnessInstance, $_) })
    $limit = if ($TimeoutMinutes -gt 0) { $TimeoutMinutes } else { 30 }
    $hostExe = (Get-Process -Id $PID).Path
    $rows = @(); $failures = 0
    foreach ($run in $runs) {
        $runMain = $run[0]; $runInv = $run[1]
        Say ("=== {0} / {1}: expected violated, limit {2} min" -f $runMain, $runInv, $limit)
        $childArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Model", $Model, "-WorkDir", $WorkDir,
                       "-Java", $Java, "-Main", $runMain, "-Invariant", $runInv, "-Share", "$Share",
                       "-MinFreeDiskPercent", "$MinFreeDiskPercent", "-IntervalSeconds", "$IntervalSeconds",
                       "-TimeoutMinutes", "$limit")
        $t0 = Get-Date
        & $hostExe @childArgs
        $code = $LASTEXITCODE
        $got = switch ($code) { 0 { "holds" } 2 { "violated" } default { "no verdict" } }
        $pass = $got -eq "violated"
        if (-not $pass) { $failures++ }
        $rows += ("{0,-4}  {1,-26} {2,-20} {3,-10} {4,6:N1} min" -f `
            $(if ($pass) { "pass" } else { "FAIL" }), $runMain, $runInv, $got, ((Get-Date) - $t0).TotalMinutes)
    }
    $table = @("model hash: $(Get-ModelHash)", "expected for every row: violated", "") + $rows +
             @("", $(if ($failures -eq 0) { "all outcomes as expected" } else { "$failures outcome(s) not as expected" }))
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $tableFile = Join-Path $WorkDir ("probes-{0}-{1}.txt" -f $Model, (Get-Date -Format "yyyyMMdd-HHmmss"))
    [System.IO.File]::WriteAllLines($tableFile, $table)
    Say "Probe table ($tableFile):"
    $table | ForEach-Object { Write-Host "  $_" }
    if ($failures -eq 0) { exit 0 } else { exit 1 }
}

# ------------------------------------------------------------------ preparation
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path

# Quint starts Apalache with the java found on the PATH, so put the given Java
# first on it.
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
    try { Invoke-Native "npm" @("ci", "--ignore-scripts") | Out-Host } finally { Pop-Location }
    if ($script:NativeExit -ne 0) { $script:NativeErrors | Out-Host; throw "npm ci failed" }
}

$hash = Get-ModelHash
$commit = "$(Invoke-Native "git" @("-C", $ModelDir, "rev-parse", "--short", "HEAD"))".Trim()
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunDir = Join-Path $WorkDir ("{0}-{1}-{2}" -f $Model, $Main, $stamp)
New-Item -ItemType Directory -Force -Path $RunDir, (Join-Path $RunDir "tmp") | Out-Null
Say ("Model {0}, commit {1}, instance {2}, run folder {3}" -f $hash, $commit, $Main, $RunDir)

# Compile the instance to TLA+.
Say "Compiling to TLA+"
$compileArgs = @("compile", "--target=tlaplus", "--main=$Main", "--invariant=$Invariant")
if ($Temporal) { $compileArgs += "--temporal=$Temporal" }
$compileArgs += $SourceFile
Push-Location $ModelDir
try { $lines = @(Invoke-Native $quint $compileArgs) } finally { Pop-Location }
$start = -1; $end = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($start -lt 0 -and $lines[$i] -match "^-+ MODULE $Main -+$") { $start = $i }
    if ($start -ge 0 -and $lines[$i] -match "^=+$") { $end = $i }
}
if ($start -lt 0 -or $end -lt 0) {
    $script:NativeErrors | Out-Host
    throw "Compilation produced no TLA+ module $Main (exit code $script:NativeExit)"
}
$spec = Join-Path $RunDir "$Main.tla"
[System.IO.File]::WriteAllLines($spec, $lines[$start..$end])

# Apalache modules the compiled specification extends.
$apalacheJar = Get-ChildItem -Path $env:QUINT_HOME -Recurse -Filter "apalache.jar" | Select-Object -First 1
if (-not $apalacheJar) { throw "apalache.jar not found under $($env:QUINT_HOME)" }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($apalacheJar.FullName)
try {
    foreach ($name in $ApalacheModules) {
        $entry = $zip.GetEntry("tla2sany/StandardModules/$name")
        if (-not $entry) { throw "$name not found in apalache.jar" }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $RunDir $name), $true)
    }
} finally { $zip.Dispose() }

# TLC itself.
$tools = Join-Path $WorkDir "tla2tools-$TlaToolsVersion.jar"
if (-not (Test-Path $tools)) {
    Say "Downloading tla2tools.jar $TlaToolsVersion"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $TlaToolsUrl -OutFile $tools -UseBasicParsing
}

$cfg = @("INIT q_init", "NEXT q_step", "INVARIANT q_inv")
if ($Temporal) { $cfg += "PROPERTY q_temporalProps" }
$viewLine = @()
if ($View) {
    $cfg += "VIEW $($Checks.view.operator)"
    $vsha = [System.Security.Cryptography.SHA256]::Create()
    $vhash = (-join ($vsha.ComputeHash([System.IO.File]::ReadAllBytes((Join-Path $ModelDir $SourceFile))) |
        ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
    $viewLine = @("view: $SourceFile $vhash, operator $($Checks.view.operator)")
    Say "View $SourceFile $vhash, operator $($Checks.view.operator)"
}
[System.IO.File]::WriteAllLines((Join-Path $RunDir "$Main.cfg"), $cfg)

# Resource limits.
$cores = [Environment]::ProcessorCount
$workers = [math]::Max(1, [math]::Floor($Share * $cores))
$memGb = [math]::Floor((Get-TotalMemoryBytes) / 1GB)
$heapGb = [math]::Max(1, [math]::Floor($memGb * $Share * 0.6))
$directGb = [math]::Max(1, [math]::Floor($memGb * $Share * 0.3))
Say ("Limits: {0} of {1} cores, heap {2} GB, direct memory {3} GB of {4} GB RAM, stop below {5}% free disk" -f `
    $workers, $cores, $heapGb, $directGb, $memGb, $MinFreeDiskPercent)

$tlcArgs = @("-XX:+UseParallelGC", "-Xmx${heapGb}g", "-XX:MaxDirectMemorySize=${directGb}g",
             "-Djava.io.tmpdir=`"$(Join-Path $RunDir 'tmp')`"", "-cp", "`"$tools`"", "tlc2.TLC",
             "-workers", "$workers", "-deadlock", "-gzip", "-checkpoint", "$CheckpointMinutes", "-metadir", "states")
if ($Recover) { $tlcArgs += @("-recover", "`"$Recover`"") }
if ($Fp -ge 0) {
    if ($Fp -gt 130) { throw "-Fp must be between 0 and 130" }
    $tlcArgs += @("-fp", "$Fp")
}
$tlcArgs += "$Main.tla"

$log = Join-Path $RunDir "tlc.log"
$started = Get-Date
$tlc = Start-Process -FilePath $Java -ArgumentList $tlcArgs -WorkingDirectory $RunDir `
    -RedirectStandardOutput $log -RedirectStandardError (Join-Path $RunDir "tlc.err") -PassThru -NoNewWindow
try { $tlc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { Say "Could not lower the priority: $_" }
Say ("TLC started, PID {0}. Log: {1}" -f $tlc.Id, $log)

# ---------------------------------------------------------------------- progress
$pattern = 'Progress\((\d+)\) at .*?: ([\d,]+) states generated.*?, ([\d,]+) distinct states found \(([\d,]+) ds/min\), ([\d,]+) states left on queue'
$lastQueue = $null; $lastTime = $null; $lastLine = $null; $trend = ""; $stoppedForDisk = $false; $stoppedForTime = $false
while (-not $tlc.HasExited) {
    # Wait in short steps so that a run which ends early is not held for a whole interval.
    $waitUntil = (Get-Date).AddSeconds($IntervalSeconds)
    while (-not $tlc.HasExited -and (Get-Date) -lt $waitUntil) { Start-Sleep -Seconds 1 }
    if ($tlc.HasExited) { break }
    $free = Get-FreeDiskPercent $RunDir
    $elapsed = (Get-Date) - $started
    $line = $null
    if (Test-Path $log) { $line = Get-Content $log -Tail 50 | Where-Object { $_ -match $pattern } | Select-Object -Last 1 }
    if ($line -and ($line -match $pattern)) {
        $depth = $Matches[1]
        $distinct = [int64]($Matches[3] -replace ",", "")
        $rate = [int64]($Matches[4] -replace ",", "")
        $queue = [int64]($Matches[5] -replace ",", "")
        if ($line -ne $lastLine -and $null -ne $lastQueue) {
            $minutes = ((Get-Date) - $lastTime).TotalMinutes
            $perMin = ($queue - $lastQueue) / [math]::Max($minutes, 0.01)
            if ($perMin -lt 0) {
                $eta = [TimeSpan]::FromMinutes($queue / (-$perMin))
                $trend = ", queue shrinking {0}/min, about {1:%d}d {1:hh}h {1:mm}m left at this rate" -f (Format-Count ([int64](-$perMin))), $eta
            } else {
                $trend = ", queue growing {0}/min, end not in sight yet" -f (Format-Count ([int64]$perMin))
            }
        }
        if ($line -ne $lastLine) { $lastQueue = $queue; $lastTime = Get-Date; $lastLine = $line }
        Say ("{0:%d}d {0:hh}:{0:mm} elapsed | depth {1} | distinct {2} (+{3}/min) | queue {4}{5} | disk free {6}%" -f `
            $elapsed, $depth, (Format-Count $distinct), (Format-Count $rate), (Format-Count $queue), $trend, $free)
    } else {
        Say ("{0:%d}d {0:hh}:{0:mm} elapsed | starting | disk free {1}%" -f $elapsed, $free)
    }
    if ($free -lt $MinFreeDiskPercent) {
        Say "Free disk space is below $MinFreeDiskPercent%: stopping TLC. The last checkpoint is kept under states."
        Stop-Process -Id $tlc.Id
        $stoppedForDisk = $true
        break
    }
    if ($TimeoutMinutes -gt 0 -and $elapsed.TotalMinutes -ge $TimeoutMinutes) {
        Say "Time limit of $TimeoutMinutes min reached: stopping TLC. This is not a result."
        Stop-Process -Id $tlc.Id
        $stoppedForTime = $true
        break
    }
}
$tlc.WaitForExit()
$ended = Get-Date

# ----------------------------------------------------------------------- summary
$text = if (Test-Path $log) { Get-Content $log } else { @() }
# TLC also estimates the probability that two distinct states shared a
# fingerprint, which could have left states unexplored; the summary keeps it.
$keys = 'No error has been found|Error:|is violated|were violated|states generated, .* distinct states found|depth of the complete state graph|Finished in|Model checking completed|calculated \(optimistic\)|based on the actual fingerprints'
$result = @($text | Where-Object { $_ -match $keys })
$fpLine = $text | Where-Object { $_ -match 'with fp \d+' } | Select-Object -First 1
$fpUsed = if ($fpLine -and ($fpLine -match 'with fp (\d+)')) { $Matches[1] } else { "" }
$stopped = $stoppedForDisk -or $stoppedForTime
$ok = ($text -match 'No error has been found').Count -gt 0 -and -not $stopped
$violated = ($text -match 'is violated|Temporal properties were violated').Count -gt 0 -and -not $stopped
$summary = @(
    "model hash: $hash",
    "commit: $commit",
    "instance: $Main, invariant: $Invariant$(if ($Temporal) { ", temporal: $Temporal" })",
    "tla2tools: $TlaToolsVersion",
    "fingerprint function: $(if ($fpUsed) { $fpUsed } else { 'not reported' })",
    ("limits: {0} workers of {1} cores, heap {2} GB, direct {3} GB" -f $workers, $cores, $heapGb, $directGb),
    "started: $($started.ToString('u')), ended: $($ended.ToString('u')), elapsed: $($ended - $started)",
    "result: $(if ($ok) { 'no error found' } elseif ($stoppedForDisk) { 'stopped for disk space, not a result' } elseif ($stoppedForTime) { 'stopped at the time limit, not a result' } elseif ($violated) { 'VIOLATED, the trace is in tlc.log' } else { 'no verdict, see tlc.log and tlc.err' })",
    ""
) + $result
if ($viewLine.Count -gt 0) { $summary = $summary[0..2] + $viewLine + $summary[3..($summary.Count - 1)] }
[System.IO.File]::WriteAllLines((Join-Path $RunDir "summary.txt"), $summary)
Say "Summary ($(Join-Path $RunDir 'summary.txt')):"
$summary | ForEach-Object { Write-Host "  $_" }
# A run with a verdict needs no checkpoint: free the disk. A run without one
# keeps its checkpoint under states, so it can continue with -Recover.
if ($ok -or $violated) {
    foreach ($d in @("states", "tmp")) {
        $path = Join-Path $RunDir $d
        if (Test-Path $path) { Remove-Item -Recurse -Force -Path $path -ErrorAction SilentlyContinue }
    }
}
if ($ok) { exit 0 } elseif ($violated) { exit 2 } else { exit 3 }
