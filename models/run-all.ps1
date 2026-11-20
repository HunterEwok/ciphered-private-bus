# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Long runs of several models one after another on a shared machine: for each
# model, the check of the TLA+ translation (run-tlc.ps1 -Probes) and the proof
# of safety from its inductive invariant (run-inductive.ps1 -Split). Each stage
# is the ordinary script with its own progress output and summary.txt; this
# script only orders them, passes the resources, and prints a table at the
# end. Works in Windows PowerShell 5.1 and PowerShell 7.
#
# -MemoryGB is the memory the runs may take together (the inductive proof gives
# half of it to Java heaps and leaves the rest to the solvers). -Parallel is the
# number of inductive checks at a time; each gets MemoryGB / 2 / Parallel of
# heap. A model whose checks.json sets "inductive.parallel" uses that number
# instead (fewer checks with more memory each, for the large membership
# instance). -TimeoutHours bounds each inductive check, so that a run fits a
# night; a check stopped at the limit has no verdict. A stage that fails does
# not stop the next one.
#
# Example:
#   powershell -ExecutionPolicy Bypass -File models\run-all.ps1 `
#     -WorkDir D:\runs -Java C:\jdk\bin\java.exe -MemoryGB 100
#
# Exit status: 0 every stage as expected, 1 otherwise.

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$Java = "java",
    [string[]]$Models = @("channels", "calls", "enrollment", "membership"),
    [string[]]$Stages = @("probes", "inductive"),
    [double]$MemoryGB = 100,
    [int]$Parallel = 6,
    [int]$TimeoutMinutes = 30,
    [int]$TimeoutHours = 0
)

$ErrorActionPreference = "Stop"
$ModelsDir = $PSScriptRoot
$OnWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'

function Say([string]$Text) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Text) }

if ($OnWindows) { $memBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
else { $memBytes = [int64](((Get-Content /proc/meminfo | Where-Object { $_ -like "MemTotal:*" }) -split "\s+")[1]) * 1024 }
$totalGb = $memBytes / 1GB
$share = [math]::Round([math]::Min(0.95, $MemoryGB / $totalGb), 3)
# Passed as text in the invariant culture, so a decimal comma never reaches the child script.
$shareText = $share.ToString([System.Globalization.CultureInfo]::InvariantCulture)
$shell = (Get-Process -Id $PID).Path

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$commit = "$(& git -C $ModelsDir rev-parse --short HEAD 2>$null)".Trim()
$ErrorActionPreference = $saved
Say ("Models {0}, stages {1}, commit {2}" -f ($Models -join ", "), ($Stages -join ", "), $commit)
Say ("Memory {0:N0} GB of {1:N0} GB (share {2}), inductive checks {3} at a time" -f $MemoryGB, $totalGb, $share, $Parallel)

$rows = @()
$failures = 0
$startedAll = Get-Date
foreach ($model in $Models) {
    foreach ($stage in $Stages) {
        if ($stage -eq "probes") {
            $script = Join-Path $ModelsDir "run-tlc.ps1"
            $stageArgs = @("-Model", $model, "-Probes", "-TimeoutMinutes", $TimeoutMinutes, "-Share", $shareText)
        } elseif ($stage -eq "inductive") {
            $script = Join-Path $ModelsDir "run-inductive.ps1"
            $ind = (Get-Content (Join-Path (Join-Path $ModelsDir $model) "checks.json") -Raw | ConvertFrom-Json).inductive
            $par = if ($ind -and $ind.parallel) { [int]$ind.parallel } else { $Parallel }
            $stageArgs = @("-Model", $model, "-Split", "-Parallel", $par, "-Share", $shareText, "-TimeoutHours", $TimeoutHours)
        } else { throw "Unknown stage $stage (probes or inductive)" }
        Say ("===== {0}: {1} =====" -f $model, $stage)
        $started = Get-Date
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script, "-WorkDir", $WorkDir, "-Java", $Java) + $stageArgs
        $saved = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        & $shell @argList
        $code = $LASTEXITCODE
        $ErrorActionPreference = $saved
        $mins = ((Get-Date) - $started).TotalMinutes
        $ok = $code -eq 0
        if (-not $ok) { $failures++ }
        $verdict = if ($ok) { "as expected" } else { "FAILED (exit $code), see its summary.txt" }
        Say ("{0}: {1}: {2} ({3:N1} min)" -f $model, $stage, $verdict, $mins)
        $rows += ("{0,-4}  {1,-12} {2,-10} {3,8:N1} min  {4}" -f $(if ($ok) { "pass" } else { "FAIL" }), $model, $stage, $mins, $verdict)
    }
}

$summary = @(
    "commit: $commit",
    "memory: $MemoryGB GB (share $share), inductive checks $Parallel at a time",
    "started: $($startedAll.ToString('u')), ended: $((Get-Date).ToString('u')), elapsed: $((Get-Date) - $startedAll)",
    ""
) + $rows + @("", "Each stage wrote its own folder with summary.txt under $WorkDir.")
$file = Join-Path $WorkDir ("run-all-{0}.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
[System.IO.File]::WriteAllLines($file, $summary)
Say "Summary ($file):"
$summary | ForEach-Object { Write-Host "  $_" }
if ($failures -eq 0) { exit 0 } else { exit 1 }
