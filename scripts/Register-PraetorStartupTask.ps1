#Requires -Version 5.1
<#
.SYNOPSIS
    Registers (or removes) a Windows Logon Scheduled Task to start the Praetor Counter-Agent
    Perimeter (`127.0.0.1:18088` Python Loopback Hub + `0.0.0.0:8088` `praetor-gate` Ed25519 Proxy).
.DESCRIPTION
    Executes `Deploy-PraetorCluster.ps1 -Node <Node> -CutoverHub` automatically at user logon so
    NodeAlpha, NodeBeta, NodeDelta, and NodeGamma never boot with an unguarded `:8088` listener.
    Note: Because `praetor-hook` blocks autonomous agents from invoking `Register-ScheduledTask`
    directly (`PERSIST-SCHTASKS-REG`), run this script interactively from an operator PowerShell prompt.
#>
param(
    [ValidateSet("node-alpha", "node-beta", "node-delta", "node-gamma")]
    [string]$Node = "node-alpha",
    [switch]$Unregister
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskName = "AgentMesh-Praetor-Perimeter-$Node"
$DeployScript = Join-Path $PSScriptRoot "Deploy-PraetorCluster.ps1"

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "[OK] Unregistered Scheduled Task '$TaskName'."
    exit 0
}

$PwshExe = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) {
    (Get-Command pwsh.exe).Source
} else {
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}

$ArgString = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$DeployScript`" -Node $Node -CutoverHub"
$Action = New-ScheduledTaskAction -Execute $PwshExe -Argument $ArgString
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Starts Praetor v0.1.0 Ed25519 LAN Gate (:8088 -> 127.0.0.1:18088) and seals Reaper persistence baselines for node '$Node'." `
    -Force | Out-Null

Write-Output "[OK] Registered Logon Scheduled Task '$TaskName' -> $PwshExe $ArgString"
