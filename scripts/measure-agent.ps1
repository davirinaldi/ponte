<#
.SYNOPSIS
    Measures the agent against its budget (RNF-12): binary size, idle memory and CPU.

.DESCRIPTION
    Samples one running agent process at a fixed interval and prints the peak and the
    average of its memory, and its CPU over the whole window. It only reads the counters
    of that process: no network, no elevation, nothing written.

    Measure a release build that is enrolled, connected and idle, after it settles:
    see docs/walkthrough.md.

.EXAMPLE
    .\scripts\measure-agent.ps1 -Binary target\release\ponte-agent.exe -Minutes 15
#>
param(
    # The agent's process. By default, the only process named ponte-agent.
    [int] $ProcessId = 0,
    # The binary to report the size of, if any.
    [string] $Binary = "",
    [double] $Minutes = 15,
    [int] $IntervalSeconds = 10
)

$ErrorActionPreference = "Stop"

# The budget of RNF-12.
$MaxBinaryMB = 15
$MaxMemoryMB = 40
$MaxCpuPercent = 1

function Find-Agent {
    if ($ProcessId -ne 0) {
        return Get-Process -Id $ProcessId
    }
    $found = @(Get-Process -Name ponte-agent -ErrorAction SilentlyContinue)
    if ($found.Count -ne 1) {
        throw "expected one ponte-agent process, found $($found.Count): pass -ProcessId"
    }
    return $found[0]
}

function MB([double] $bytes) {
    return [math]::Round($bytes / 1MB, 1)
}

function Verdict([bool] $within) {
    if ($within) { return "within" } else { return "OVER" }
}

if ($Binary -ne "") {
    $size = (Get-Item $Binary).Length
    "binary        {0,8} MB   (limit {1} MB, {2})" -f (MB $size), $MaxBinaryMB, (Verdict ((MB $size) -lt $MaxBinaryMB))
}

$agent = Find-Agent
$cores = [Environment]::ProcessorCount
$samples = [math]::Max(1, [int][math]::Ceiling($Minutes * 60 / $IntervalSeconds))
"process       {0} (pid {1}), {2} samples every {3} s, {4} logical processors" -f $agent.ProcessName, $agent.Id, $samples, $IntervalSeconds, $cores

$clock = [Diagnostics.Stopwatch]::StartNew()
$agent.Refresh()
$cpuStart = $agent.TotalProcessorTime
$working = @()
$private = @()
for ($i = 0; $i -lt $samples; $i++) {
    Start-Sleep -Seconds $IntervalSeconds
    $agent.Refresh()
    if ($agent.HasExited) {
        throw "the agent exited during the measurement"
    }
    $working += $agent.WorkingSet64
    $private += $agent.PrivateMemorySize64
}
$wall = $clock.Elapsed.TotalSeconds
$cpu = ($agent.TotalProcessorTime - $cpuStart).TotalSeconds

$ws = $working | Measure-Object -Average -Maximum
$pv = $private | Measure-Object -Average -Maximum
$cpuCore = 100 * $cpu / $wall
$cpuMachine = $cpuCore / $cores

"working set   avg {0,6} MB, peak {1,6} MB   (limit {2} MB, {3})" -f (MB $ws.Average), (MB $ws.Maximum), $MaxMemoryMB, (Verdict ((MB $ws.Maximum) -lt $MaxMemoryMB))
"private bytes avg {0,6} MB, peak {1,6} MB" -f (MB $pv.Average), (MB $pv.Maximum)
"cpu           {0:N3} s in {1:N0} s: {2:N3}% of one core, {3:N4}% of the machine   (limit {4}%, {5})" -f $cpu, $wall, $cpuCore, $cpuMachine, $MaxCpuPercent, (Verdict ($cpuCore -lt $MaxCpuPercent))
