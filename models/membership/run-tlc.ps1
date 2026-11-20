# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Exhaustive TLC run of the membership model on a shared machine, with
# progress output. Works in Windows PowerShell 5.1 and PowerShell 7.
#
# It compiles an instance of instances.qnt to TLA+, starts TLC at below-normal
# priority within a share of the CPU cores and memory, prints progress every
# interval, stops TLC if free disk space falls below a limit, and writes a
# summary at the end. Everything is written under -WorkDir.
#
# Example:
#   powershell -ExecutionPolicy Bypass -File models\membership\run-tlc.ps1 `
#     -WorkDir D:\runs -Java C:\jdk\bin\java.exe
#
# Ctrl+C stops only the progress output; TLC keeps running. To stop TLC, use
# Stop-Process with the PID the script prints. To continue a stopped run from
# its last checkpoint, pass -Recover with the checkpoint folder (states\<date>).

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$Java = "java",
    [string]$Main = "tiny_tlc",
    [string]$Invariant = "safety",
    [string]$Temporal = "",
    [double]$Share = 0.85,
    [int]$MinFreeDiskPercent = 15,
    [int]$IntervalSeconds = 60,
    [string]$Recover = ""
)

$ErrorActionPreference = "Stop"
$TlaToolsVersion = "1.7.4"
$TlaToolsUrl = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
$ApalacheModules = @("Apalache.tla", "Variants.tla", "Option.tla", "__apalache_folds.tla", "__apalache_internal.tla")

$ModelDir = $PSScriptRoot
$ModelsDir = Split-Path -Parent $ModelDir
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
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $ModelDir "membership.qnt")) +
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
$RunDir = Join-Path $WorkDir ("{0}-{1}" -f $Main, $stamp)
New-Item -ItemType Directory -Force -Path $RunDir, (Join-Path $RunDir "tmp") | Out-Null
Say ("Model {0}, commit {1}, instance {2}, run folder {3}" -f $hash, $commit, $Main, $RunDir)

# Compile the instance to TLA+.
Say "Compiling to TLA+"
$compileArgs = @("compile", "--target=tlaplus", "--main=$Main", "--invariant=$Invariant")
if ($Temporal) { $compileArgs += "--temporal=$Temporal" }
$compileArgs += "instances.qnt"
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
             "-workers", "$workers", "-deadlock", "-checkpoint", "60", "-metadir", "states")
if ($Recover) { $tlcArgs += @("-recover", "`"$Recover`"") }
$tlcArgs += "$Main.tla"

$log = Join-Path $RunDir "tlc.log"
$started = Get-Date
$tlc = Start-Process -FilePath $Java -ArgumentList $tlcArgs -WorkingDirectory $RunDir `
    -RedirectStandardOutput $log -RedirectStandardError (Join-Path $RunDir "tlc.err") -PassThru -NoNewWindow
try { $tlc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { Say "Could not lower the priority: $_" }
Say ("TLC started, PID {0}. Log: {1}" -f $tlc.Id, $log)

# ---------------------------------------------------------------------- progress
$pattern = 'Progress\((\d+)\) at .*?: ([\d,]+) states generated.*?, ([\d,]+) distinct states found \(([\d,]+) ds/min\), ([\d,]+) states left on queue'
$lastQueue = $null; $lastTime = $null; $lastLine = $null; $trend = ""; $stoppedForDisk = $false
while (-not $tlc.HasExited) {
    Start-Sleep -Seconds $IntervalSeconds
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
}
$tlc.WaitForExit()
$ended = Get-Date

# ----------------------------------------------------------------------- summary
$text = if (Test-Path $log) { Get-Content $log } else { @() }
$keys = 'No error has been found|Error:|is violated|states generated, .* distinct states found|depth of the complete state graph|Finished in|Model checking completed'
$result = @($text | Where-Object { $_ -match $keys })
$ok = ($text -match 'No error has been found').Count -gt 0 -and -not $stoppedForDisk
$summary = @(
    "model hash: $hash",
    "commit: $commit",
    "instance: $Main, invariant: $Invariant$(if ($Temporal) { ", temporal: $Temporal" })",
    "tla2tools: $TlaToolsVersion",
    ("limits: {0} workers of {1} cores, heap {2} GB, direct {3} GB" -f $workers, $cores, $heapGb, $directGb),
    "started: $($started.ToString('u')), ended: $($ended.ToString('u')), elapsed: $($ended - $started)",
    "result: $(if ($ok) { 'no error found' } elseif ($stoppedForDisk) { 'stopped for disk space, not a result' } elseif (($text -match 'is violated').Count -gt 0) { 'VIOLATED, the trace is in tlc.log' } else { 'no verdict, see tlc.log and tlc.err' })",
    ""
) + $result
[System.IO.File]::WriteAllLines((Join-Path $RunDir "summary.txt"), $summary)
Say "Summary ($(Join-Path $RunDir 'summary.txt')):"
$summary | ForEach-Object { Write-Host "  $_" }
if ($ok) { exit 0 } else { exit 1 }
