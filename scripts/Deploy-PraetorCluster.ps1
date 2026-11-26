#Requires -Version 5.1
<#
.SYNOPSIS
    Provisions and arms the Praetor Counter-Agent Fleet across NodeAlpha, NodeBeta, NodeDelta, and NodeGamma.
.DESCRIPTION
    1. Mints Ed25519 node signing key (owner-only ACLs) and registers node public key into both local and repo `cluster_roster.json`.
    2. Mints XChaCha20-Poly1305 baseline sealing key and arms `praetor-reaper` over protected surfaces.
    3. Rebinds `Start-AgentHubServer.py` strictly onto loopback (`127.0.0.1:18088`) and launches
       `praetor-gate` on external `0.0.0.0:8088` when `-CutoverHub` is passed.
#>
param(
    [ValidateSet("node-alpha", "node-beta", "node-delta", "node-gamma")]
    [string]$Node = "node-alpha",
    [string]$ConfigDir = "$env:LOCALAPPDATA\Praetor",
    [switch]$CutoverHub,
    [switch]$ServeForeground,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$GateExe = Join-Path $RepoRoot "target\release\praetor-gate.exe"
$HookExe = Join-Path $RepoRoot "target\release\praetor-hook.exe"
$ReaperExe = Join-Path $RepoRoot "target\release\praetor-reaper.exe"
$RepoRoster = Join-Path $RepoRoot "cluster_roster.json"
$LocalRoster = Join-Path $ConfigDir "cluster_roster.json"

Write-Output "[Praetor] Target Node: $Node | Config Vault: $ConfigDir | CutoverHub: $CutoverHub | DryRun: $DryRun"

if ($DryRun) {
    Write-Output "[DryRun] 1. Build release binaries: cargo build --release --manifest-path `"$RepoRoot\Cargo.toml`""
    Write-Output "[DryRun] 2. Mint node Ed25519 key: $GateExe keygen --node $Node --secret-out `"$ConfigDir\$Node.node.key`""
    Write-Output "[DryRun] 3. Register pubkey in $RepoRoster & $LocalRoster"
    Write-Output "[DryRun] 4. Mint Reaper seal key & arm protected surfaces (`mcp_config.json`, hooks, `skills-meta-index.json`)."
    Write-Output "[DryRun] 5. Rebind Start-AgentHubServer.py --host 127.0.0.1 --port 18088 behind praetor-gate on 0.0.0.0:8088"
    exit 0
}

function Assert-NativeSuccess {
    param([string]$StepName)
    if ($LASTEXITCODE -ne 0) {
        throw "Step '$StepName' failed with exit code $LASTEXITCODE."
    }
}

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
# Lock config vault directory ACLs BEFORE writing any keys or baselines (`[D3]`)
$OwnerPrincipal = "$env:USERDOMAIN\$env:USERNAME"
& icacls $ConfigDir /inheritance:r /grant:r "${OwnerPrincipal}:(OI)(CI)F" | Out-Null
Assert-NativeSuccess "icacls lock $ConfigDir"

$ForensicDir = Join-Path $ConfigDir "forensics"
New-Item -ItemType Directory -Force -Path $ForensicDir | Out-Null

$NodeKeyFile = Join-Path $ConfigDir "$Node.node.key"
$PubKeyFile = Join-Path $ConfigDir "$Node.node.pub.json"
if (-not (Test-Path $NodeKeyFile) -or -not (Test-Path $PubKeyFile)) {
    $KeyJson = & $GateExe keygen --node $Node --secret-out $NodeKeyFile
    Assert-NativeSuccess "praetor-gate keygen"
    Set-Content -Path $PubKeyFile -Value ($KeyJson -join "`n") -Encoding UTF8
}

$PubMeta = Get-Content -Path $PubKeyFile -Raw | ConvertFrom-Json
$VkHex = $PubMeta.verifying_key_hex

if (Test-Path $RepoRoster) {
    Copy-Item -Path $RepoRoster -Destination $LocalRoster -Force
}
& $GateExe init-roster --roster-out $RepoRoster --peer "$Node=$VkHex" | Out-Null
Assert-NativeSuccess "praetor-gate init-roster"
Copy-Item -Path $RepoRoster -Destination $LocalRoster -Force

$ReaperKeyFile = Join-Path $ConfigDir "$Node.reaper.key"
if (-not (Test-Path $ReaperKeyFile)) {
    & $ReaperExe keygen --key-out $ReaperKeyFile | Out-Null
    Assert-NativeSuccess "praetor-reaper keygen"
}

$ProtectedCandidates = @(
    "$env:USERPROFILE\.gemini\agent-ide\mcp_config.json",
    "$env:USERPROFILE\.gemini\config\hooks.json",
    "C:\Workspaces\global_workspace\.agents\hooks.json",
    "C:\Workspaces\global_workspace\.agents\hooks\validate-tool-call.mjs",
    "C:\Workspaces\global_workspace\.agents\hooks\session-bootstrap.ps1",
    "C:\Users\user_d899f281\AgentMesh\Estate\Registry\skills-meta-index.json"
) | ForEach-Object {
    if (Test-Path -LiteralPath $_) {
        $item = Get-Item -LiteralPath $_ -Force
        if ($null -ne $item.LinkType -and $item.Target) {
            $target = @($item.Target)[0]
            if (-not [System.IO.Path]::IsPathRooted($target)) {
                $target = Join-Path (Split-Path -Parent $item.FullName) $target
            }
            if (Test-Path -LiteralPath $target -PathType Leaf) {
                (Resolve-Path -LiteralPath $target).Path
            }
        } elseif (-not $item.PSIsContainer) {
            $item.FullName
        }
    }
} | Select-Object -Unique

if ($ProtectedCandidates.Count -gt 0) {
    $DbPath = Join-Path $ConfigDir "praetor_baselines.db"
    $StagingDb = "$DbPath.staging"
    $BackupDb = "$DbPath.prev"
    foreach ($ext in @("", "-wal", "-shm")) {
        $f = "$StagingDb$ext"
        if (Test-Path -LiteralPath $f) {
            Remove-Item -LiteralPath $f -Force
        }
    }
    $ReaperArgs = @("arm", "--db", $StagingDb, "--key-file", $ReaperKeyFile)
    foreach ($p in $ProtectedCandidates) {
        $ReaperArgs += @("--paths", $p)
    }
    $ArmOut = & $ReaperExe @ReaperArgs
    Assert-NativeSuccess "praetor-reaper arm (staging)"
    # Only swap staging DB into production AFTER staging arm verified (`[D1]`)
    foreach ($ext in @("-wal", "-shm")) {
        if (Test-Path -LiteralPath "$DbPath$ext") { Remove-Item -LiteralPath "$DbPath$ext" -Force }
    }
    if (Test-Path -LiteralPath $DbPath) {
        Move-Item -LiteralPath $DbPath -Destination $BackupDb -Force
    }
    foreach ($ext in @("-wal", "-shm")) {
        if (Test-Path -LiteralPath "$StagingDb$ext") { Remove-Item -LiteralPath "$StagingDb$ext" -Force }
    }
    Move-Item -LiteralPath $StagingDb -Destination $DbPath -Force
    $ArmOut
}

if ($CutoverHub -or $ServeForeground) {
    # Terminate any existing listener on :8088 (single PID only, preserving child worker processes)
    $Listeners8088 = @(Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue)
    foreach ($conn in $Listeners8088) {
        if ($conn.OwningProcess -gt 4) {
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 400

    # Verify loopback upstream on 127.0.0.1:18088 (`[D2]`)
    $LoopbackHub = @(Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 18088 -State Listen -ErrorAction SilentlyContinue)
    if ($LoopbackHub.Count -eq 0) {
        $HubScript = @(
            "C:\Workspaces\mesh-ledger\scripts\intranet-hosts-sync\Start-AgentHubServer.py",
            "C:\Workspaces\mesh-bus\scripts\intranet-hosts-sync\Start-AgentHubServer.py",
            "C:\Workspaces\global_workspace\mesh-bus\repos\scripts\intranet-hosts-sync\Start-AgentHubServer.py"
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        $PyExe = if (Test-Path "C:\Python314\pythonw.exe") { "C:\Python314\pythonw.exe" } else { "python" }
        Start-Process -FilePath $PyExe -ArgumentList @("`"$HubScript`"", "--host", "127.0.0.1", "--port", "18088") -WindowStyle Hidden
        Start-Sleep -Milliseconds 800
    }

    if ($ServeForeground) {
        Write-Output "[Praetor] Serving praetor-gate in foreground on 0.0.0.0:8088 -> 127.0.0.1:18088..."
        & $GateExe serve --node $Node --listen 0.0.0.0:8088 --upstream 127.0.0.1:18088 --roster-file $LocalRoster --forensic-dir $ForensicDir
        exit $LASTEXITCODE
    }

    # Launch praetor-gate detached on external 0.0.0.0:8088 -> 127.0.0.1:18088
    Start-Process -FilePath $GateExe -ArgumentList @(
        "serve",
        "--node", $Node,
        "--listen", "0.0.0.0:8088",
        "--upstream", "127.0.0.1:18088",
        "--roster-file", "`"$LocalRoster`"",
        "--forensic-dir", "`"$ForensicDir`""
    ) -WindowStyle Hidden

    # Verify live `:8088` praetor-gate listener + HTTP `/health` readiness before declaring cutover `[OK]` (`[D2]`)
    $Ready = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 300
        try {
            $H = Invoke-RestMethod -Uri "http://127.0.0.1:8088/health" -TimeoutSec 2 -ErrorAction Stop
            if ($H.status -eq "ok") {
                $Ready = $true
                break
            }
        } catch {
            continue
        }
    }
    if (-not $Ready) {
        throw "Cutover verification failed: http://127.0.0.1:8088/health did not respond 'ok'."
    }
    Write-Output "[OK] Cutover complete and verified: 0.0.0.0:8088 (praetor-gate) -> 127.0.0.1:18088 (Python Loopback Hub)."
}

Write-Output "[OK] Praetor node '$Node' provisioned under $ConfigDir (pubkey=$VkHex)."
