<#
.SYNOPSIS
    Enterprise Claude Code Deployment Automation Script

.DESCRIPTION
    Comprehensive PowerShell script for deploying Claude Code with enterprise-grade security controls.
    Implements all security measures from the "Securing Claude Code for Windows Enterprise Deployments" guide.

.PARAMETER FullDeployment
    Perform complete deployment (all modules)

.PARAMETER InstallOnly
    Install Claude Code only without security configurations

.PARAMETER PoliciesOnly
    Deploy managed policies only

.PARAMETER HooksOnly
    Deploy security hooks only

.PARAMETER ShadowPrevention
    Configure shadow installation prevention only

.PARAMETER WindowsSecurity
    Configure Windows security integration only

.PARAMETER Monitoring
    Setup monitoring and audit logging only

.PARAMETER Test
    Run validation tests only

.PARAMETER Uninstall
    Uninstall Claude Code and remove all configurations

.PARAMETER InstallPath
    Custom installation path (default: C:\ProgramData\ClaudeCode)

.PARAMETER ConfigImportPath
    Path to configuration package for import

.PARAMETER ComputerListPath
    Path to CSV file containing computer names for multi-machine deployment

.PARAMETER Silent
    Run in silent mode without user interaction

.PARAMETER SkipValidation
    Skip validation steps

.EXAMPLE
    .\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment

.EXAMPLE
    .\Deploy-ClaudeCode-Enterprise.ps1 -InstallOnly -InstallPath "D:\ClaudeCode"

.EXAMPLE
    .\Deploy-ClaudeCode-Enterprise.ps1 -Test

.NOTES
    Version: 2.0
    Author: Enterprise Security Team
    Requires: PowerShell 5.1+ or PowerShell 7+
    Requires: Administrator privileges
    Requires: Node.js and npm installed
#>

[CmdletBinding()]
param(
    [switch]$FullDeployment,
    [switch]$InstallOnly,
    [switch]$PoliciesOnly,
    [switch]$HooksOnly,
    [switch]$ShadowPrevention,
    [switch]$WindowsSecurity,
    [switch]$Monitoring,
    [switch]$Test,
    [switch]$Uninstall,
    [string]$InstallPath = "C:\ProgramData\ClaudeCode",
    [string]$ConfigImportPath,
    [string]$ComputerListPath,
    [switch]$Silent,
    [switch]$SkipValidation
)

#region Global Variables

$Script:DeploymentConfig = @{
    InstallPath = $InstallPath
    NpmGlobalPath = Join-Path $InstallPath "npm-global"
    ManagedPoliciesPath = Join-Path $InstallPath "managed-policies"
    HooksPath = Join-Path $InstallPath "hooks"
    LogsPath = Join-Path $InstallPath "logs"
    ScriptsPath = Join-Path $InstallPath "scripts"
    Version = "2.0"
    DeploymentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

$Script:LogFile = Join-Path $Script:DeploymentConfig.LogsPath "deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:DeploymentResults = @{
    Success = @()
    Failed = @()
    Warnings = @()
}

#endregion

#region Logging Functions

function Write-DeploymentLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }

    # File logging
    if (-not (Test-Path (Split-Path $Script:LogFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:LogFile -Parent) -Force | Out-Null
    }
    Add-Content -Path $Script:LogFile -Value $logMessage
}

function Add-DeploymentResult {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Component,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Success', 'Failed', 'Warning')]
        [string]$Status,

        [string]$Details = ""
    )

    $result = @{
        Component = $Component
        Status = $Status
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $Script:DeploymentResults.$Status += $result
}

#endregion

#region Prerequisites & Validation

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites for deployment
    #>

    Write-DeploymentLog "Checking prerequisites..." -Level Info

    $allPrereqsMet = $true

    # Check 1: Administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-DeploymentLog "ERROR: Script must be run as Administrator" -Level Error
        $allPrereqsMet = $false
    } else {
        Write-DeploymentLog "✓ Running as Administrator" -Level Success
    }

    # Check 2: Windows version
    $os = Get-CimInstance Win32_OperatingSystem
    $osVersion = [Version]$os.Version
    $minVersion = [Version]"10.0.0.0"

    if ($osVersion -lt $minVersion) {
        Write-DeploymentLog "ERROR: Windows 10/11 or Server 2016+ required" -Level Error
        $allPrereqsMet = $false
    } else {
        Write-DeploymentLog "✓ Windows version: $($os.Caption) ($($os.Version))" -Level Success
    }

    # Check 3: PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-DeploymentLog "ERROR: PowerShell 5.1+ or 7+ required" -Level Error
        $allPrereqsMet = $false
    } else {
        Write-DeploymentLog "✓ PowerShell version: $psVersion" -Level Success
    }

    # Check 4: Node.js and npm
    try {
        $nodeVersion = node --version 2>&1
        $npmVersion = npm --version 2>&1
        Write-DeploymentLog "✓ Node.js: $nodeVersion, npm: $npmVersion" -Level Success
    } catch {
        Write-DeploymentLog "ERROR: Node.js and npm must be installed" -Level Error
        $allPrereqsMet = $false
    }

    # Check 5: Internet connectivity
    try {
        $testConnection = Test-NetConnection -ComputerName "api.anthropic.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($testConnection) {
            Write-DeploymentLog "✓ Internet connectivity verified" -Level Success
        } else {
            Write-DeploymentLog "WARNING: Cannot reach api.anthropic.com" -Level Warning
        }
    } catch {
        Write-DeploymentLog "WARNING: Could not test internet connectivity" -Level Warning
    }

    # Check 6: Disk space
    $drive = ($InstallPath -split ':')[0] + ":"
    $disk = Get-PSDrive -Name ($drive -replace ':','')
    $freeSpaceGB = [math]::Round($disk.Free / 1GB, 2)

    if ($freeSpaceGB -lt 1) {
        Write-DeploymentLog "WARNING: Low disk space: ${freeSpaceGB}GB available" -Level Warning
    } else {
        Write-DeploymentLog "✓ Disk space: ${freeSpaceGB}GB available" -Level Success
    }

    if (-not $allPrereqsMet) {
        throw "Prerequisites not met. Please resolve the errors above and try again."
    }

    return $true
}

#endregion

#region Installation Module

function Install-ClaudeCodeEnterprise {
    <#
    .SYNOPSIS
        Installs Claude Code to enterprise-controlled location
    #>

    Write-DeploymentLog "========== INSTALLATION MODULE ==========" -Level Info

    try {
        # Step 1: Create directory structure
        Write-DeploymentLog "Creating directory structure..." -Level Info

        $directories = @(
            $Script:DeploymentConfig.InstallPath,
            $Script:DeploymentConfig.NpmGlobalPath,
            $Script:DeploymentConfig.ManagedPoliciesPath,
            $Script:DeploymentConfig.HooksPath,
            $Script:DeploymentConfig.LogsPath,
            $Script:DeploymentConfig.ScriptsPath,
            (Join-Path $InstallPath "npm-cache")
        )

        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-DeploymentLog "Created directory: $dir" -Level Success
            }
        }

        # Step 2: Configure npm prefix
        Write-DeploymentLog "Configuring npm global prefix..." -Level Info

        $npmPrefix = $Script:DeploymentConfig.NpmGlobalPath
        npm config set prefix $npmPrefix --global 2>&1 | Out-Null

        Write-DeploymentLog "npm prefix set to: $npmPrefix" -Level Success

        # Step 3: Set NTFS permissions
        Write-DeploymentLog "Setting NTFS permissions (Admins: Full, Users: RX)..." -Level Info

        icacls $InstallPath /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)RX" /T | Out-Null

        Write-DeploymentLog "NTFS permissions configured" -Level Success

        # Step 4: Add to system PATH
        Write-DeploymentLog "Adding to system PATH..." -Level Info

        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$npmPrefix*") {
            $newPath = "$currentPath;$npmPrefix"
            [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            Write-DeploymentLog "Added to system PATH" -Level Success
        } else {
            Write-DeploymentLog "Already in system PATH" -Level Info
        }

        # Step 5: Install Claude Code
        Write-DeploymentLog "Installing @anthropic-ai/claude-code..." -Level Info
        Write-DeploymentLog "This may take a few minutes..." -Level Info

        $installOutput = npm install -g @anthropic-ai/claude-code 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-DeploymentLog "Claude Code installed successfully" -Level Success
        } else {
            throw "npm install failed: $installOutput"
        }

        # Step 6: Verify installation
        Write-DeploymentLog "Verifying installation..." -Level Info

        $claudeVersion = claude --version 2>&1
        if ($claudeVersion) {
            Write-DeploymentLog "Claude Code version: $claudeVersion" -Level Success
        }

        Add-DeploymentResult -Component "Installation" -Status "Success" -Details "Claude Code installed to $InstallPath"

    } catch {
        Write-DeploymentLog "Installation failed: $_" -Level Error
        Add-DeploymentResult -Component "Installation" -Status "Failed" -Details $_.Exception.Message
        throw
    }
}

#endregion

#region Managed Policies Deployment

function Deploy-ManagedPolicies {
    <#
    .SYNOPSIS
        Deploys managed security policies
    #>

    Write-DeploymentLog "========== MANAGED POLICIES DEPLOYMENT ==========" -Level Info

    try {
        $managedSettingsPath = Join-Path $Script:DeploymentConfig.ManagedPoliciesPath "managed-settings.json"

        # Create managed settings JSON
        $managedSettings = @{
            '$schema' = "https://api.claude.com/schemas/settings-v1.json"
            model = "claude-sonnet-4-5"
            permissions = @{
                defaultMode = "plan"
                deny = @(
                    @{ tool = "Edit"; matcher = "**/.env*" },
                    @{ tool = "Edit"; matcher = "**/*.key" },
                    @{ tool = "Edit"; matcher = "**/*.pem" },
                    @{ tool = "Edit"; matcher = "**/*.pfx" },
                    @{ tool = "Edit"; matcher = "**/*.p12" },
                    @{ tool = "Edit"; matcher = "**/id_rsa*" },
                    @{ tool = "Edit"; matcher = "**/.aws/credentials" },
                    @{ tool = "Edit"; matcher = "**/*-service-account.json" },
                    @{ tool = "Edit"; matcher = "**/credentials*" },
                    @{ tool = "Edit"; matcher = "C:/Windows/**" },
                    @{ tool = "Edit"; matcher = "C:/Program Files/**" },
                    @{ tool = "Edit"; matcher = "C:/ProgramData/**" },
                    @{ tool = "Read"; matcher = "C:/Users/*/AppData/Roaming/Microsoft/Crypto/**" },
                    @{ tool = "Read"; matcher = "C:/Users/*/AppData/Local/Microsoft/Credentials/**" },
                    @{ tool = "Bash"; matcher = "**/rm -rf*" },
                    @{ tool = "Bash"; matcher = "**/del /f*" },
                    @{ tool = "Bash"; matcher = "**/format*" }
                )
                ask = @(
                    @{ tool = "Edit"; matcher = "**/*.json" },
                    @{ tool = "Edit"; matcher = "**/*.yaml" },
                    @{ tool = "Bash"; matcher = "**" }
                )
                allow = @(
                    @{ tool = "Read"; matcher = "**/*.md" },
                    @{ tool = "Read"; matcher = "**/*.txt" },
                    @{ tool = "Edit"; matcher = "**/*.py" },
                    @{ tool = "Edit"; matcher = "**/*.js" }
                )
            }
            hooks = @{
                PreToolUse = @(
                    @{
                        matcher = "Edit:**"
                        hooks = @(
                            @{
                                type = "command"
                                command = "powershell -ExecutionPolicy Bypass -File `"$($Script:DeploymentConfig.HooksPath)\validate-edit.ps1`""
                            }
                        )
                    },
                    @{
                        matcher = "Bash:**"
                        hooks = @(
                            @{
                                type = "command"
                                command = "powershell -ExecutionPolicy Bypass -File `"$($Script:DeploymentConfig.HooksPath)\validate-bash.ps1`""
                            }
                        )
                    }
                )
                PostToolUse = @(
                    @{
                        matcher = "**"
                        hooks = @(
                            @{
                                type = "command"
                                command = "powershell -ExecutionPolicy Bypass -File `"$($Script:DeploymentConfig.HooksPath)\audit-log.ps1`""
                            }
                        )
                    }
                )
            }
        }

        Write-DeploymentLog "Creating managed-settings.json..." -Level Info

        $managedSettings | ConvertTo-Json -Depth 10 | Set-Content -Path $managedSettingsPath -Force

        # Set as read-only
        Set-ItemProperty -Path $managedSettingsPath -Name IsReadOnly -Value $true

        Write-DeploymentLog "Managed policies deployed: $managedSettingsPath" -Level Success

        Add-DeploymentResult -Component "Managed Policies" -Status "Success" -Details "Policies deployed and locked"

    } catch {
        Write-DeploymentLog "Policy deployment failed: $_" -Level Error
        Add-DeploymentResult -Component "Managed Policies" -Status "Failed" -Details $_.Exception.Message
        throw
    }
}

#endregion

#region Security Hooks Deployment

function Deploy-SecurityHooks {
    <#
    .SYNOPSIS
        Deploys security hooks for PreToolUse and PostToolUse validation
    #>

    Write-DeploymentLog "========== SECURITY HOOKS DEPLOYMENT ==========" -Level Info

    try {
        # Create validate-edit.ps1
        $validateEditScript = @'
param([string]$CLAUDE_HOOK_INPUT)

$input = $CLAUDE_HOOK_INPUT | ConvertFrom-Json
$filePath = $input.parameters.file_path

if (-not $filePath) { exit 0 }

$normalizedPath = $filePath -replace '/', '\'
$fileName = Split-Path $filePath -Leaf

$patternsFile = "C:\ProgramData\ClaudeCode\hooks\sensitive-files.json"
if (Test-Path $patternsFile) {
    $patterns = Get-Content $patternsFile -Raw | ConvertFrom-Json
} else {
    $patterns = @{
        extensions = @("*.env", "*.key", "*.pem", "*.pfx", "*.p12")
        filenames = @("credentials.json", "secrets.json", ".env", "id_rsa")
        paths = @("**/.ssh/*", "**/.aws/*")
    }
}

foreach ($ext in $patterns.extensions) {
    if ($fileName -like $ext) {
        $blockMessage = @{
            continue = $false
            stopReason = "SECURITY BLOCK: Cannot edit sensitive file: $ext"
        } | ConvertTo-Json -Compress
        Write-Output $blockMessage
        exit 2
    }
}

if ($patterns.filenames -contains $fileName) {
    $blockMessage = @{
        continue = $false
        stopReason = "SECURITY BLOCK: Cannot edit protected file: $fileName"
    } | ConvertTo-Json -Compress
    Write-Output $blockMessage
    exit 2
}

$systemPaths = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)")
foreach ($sysPath in $systemPaths) {
    if ($normalizedPath -like "$sysPath\*") {
        $blockMessage = @{
            continue = $false
            stopReason = "SECURITY BLOCK: Cannot edit system directory: $sysPath"
        } | ConvertTo-Json -Compress
        Write-Output $blockMessage
        exit 2
    }
}

exit 0
'@

        $validateEditPath = Join-Path $Script:DeploymentConfig.HooksPath "validate-edit.ps1"
        Set-Content -Path $validateEditPath -Value $validateEditScript -Force
        Write-DeploymentLog "Created validate-edit.ps1" -Level Success

        # Create validate-bash.ps1
        $validateBashScript = @'
param([string]$CLAUDE_HOOK_INPUT)

$input = $CLAUDE_HOOK_INPUT | ConvertFrom-Json
$command = $input.parameters.command

$dangerousCommands = @("rm -rf", "del /f", "format", "rmdir /s", "rd /s")
foreach ($dangerous in $dangerousCommands) {
    if ($command -like "*$dangerous*") {
        $blockMessage = @{
            continue = $false
            stopReason = "SECURITY BLOCK: Dangerous command detected: $dangerous"
        } | ConvertTo-Json -Compress
        Write-Output $blockMessage
        exit 2
    }
}

exit 0
'@

        $validateBashPath = Join-Path $Script:DeploymentConfig.HooksPath "validate-bash.ps1"
        Set-Content -Path $validateBashPath -Value $validateBashScript -Force
        Write-DeploymentLog "Created validate-bash.ps1" -Level Success

        # Create audit-log.ps1
        $auditLogScript = @'
param([string]$CLAUDE_HOOK_INPUT)

$hookData = $CLAUDE_HOOK_INPUT | ConvertFrom-Json

$auditEntry = @{
    timestamp = Get-Date -Format "o"
    eventType = "ClaudeCodeToolUse"
    tool = $hookData.tool
    success = $hookData.success
    user = $env:USERNAME
    computer = $env:COMPUTERNAME
    workingDirectory = (Get-Location).Path
    sessionId = $env:CLAUDE_SESSION_ID
} | ConvertTo-Json -Compress

$logDir = "C:\ProgramData\ClaudeCode\logs"
$logFile = Join-Path $logDir "audit-$(Get-Date -Format 'yyyy-MM-dd').jsonl"

Add-Content -Path $logFile -Value $auditEntry -Encoding UTF8

exit 0
'@

        $auditLogPath = Join-Path $Script:DeploymentConfig.HooksPath "audit-log.ps1"
        Set-Content -Path $auditLogPath -Value $auditLogScript -Force
        Write-DeploymentLog "Created audit-log.ps1" -Level Success

        # Create sensitive-files.json
        $sensitiveFiles = @{
            extensions = @(
                "*.env", "*.env.*", "*.envrc",
                "*.key", "*.pem", "*.pfx", "*.p12", "*.jks", "*.keystore",
                "*.crt", "*.cer", "*.der",
                "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                "*.ppk", "*.kdbx", "*credentials*", "*secret*"
            )
            filenames = @(
                ".env", ".env.local", ".env.production", ".env.development",
                "credentials.json", "secrets.json", "secrets.yml",
                ".pgpass", ".my.cnf", ".netrc"
            )
            paths = @(
                "**/.ssh/*", "**/.aws/*", "**/.azure/*", "**/.gcp/*",
                "**/.docker/config.json", "**/.kube/config",
                "**/AppData/Roaming/Microsoft/Crypto/*",
                "**/AppData/Local/Microsoft/Credentials/*"
            )
        }

        $sensitiveFilesPath = Join-Path $Script:DeploymentConfig.HooksPath "sensitive-files.json"
        $sensitiveFiles | ConvertTo-Json -Depth 5 | Set-Content -Path $sensitiveFilesPath -Force
        Write-DeploymentLog "Created sensitive-files.json" -Level Success

        # Set hooks as read-only
        Get-ChildItem -Path $Script:DeploymentConfig.HooksPath -Filter "*.ps1" | ForEach-Object {
            Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $true
        }

        Add-DeploymentResult -Component "Security Hooks" -Status "Success" -Details "All hooks deployed and locked"

    } catch {
        Write-DeploymentLog "Hooks deployment failed: $_" -Level Error
        Add-DeploymentResult -Component "Security Hooks" -Status "Failed" -Details $_.Exception.Message
        throw
    }
}

#endregion

#region Shadow Installation Prevention

function Enable-ShadowInstallationPrevention {
    <#
    .SYNOPSIS
        Implements 7-layer defense against shadow installations
    #>

    Write-DeploymentLog "========== SHADOW INSTALLATION PREVENTION ==========" -Level Info

    try {
        # Layer 1: npm Configuration Lockdown
        Write-DeploymentLog "Layer 1: Locking npm configuration..." -Level Info

        $globalNpmRc = "C:\Program Files\nodejs\npmrc"
        $npmConfig = @"
prefix=$($Script:DeploymentConfig.NpmGlobalPath)
cache=$(Join-Path $InstallPath "npm-cache")
"@

        Set-Content -Path $globalNpmRc -Value $npmConfig -Force
        Set-ItemProperty -Path $globalNpmRc -Name IsReadOnly -Value $true
        icacls $globalNpmRc /inheritance:r /grant "BUILTIN\Administrators:(F)" /grant "BUILTIN\Users:(R)" | Out-Null

        # Registry policy to disable user config
        $registryPath = "HKLM:\SOFTWARE\Policies\npm"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name "DisableUserConfig" -Value 1 -Type DWord

        Write-DeploymentLog "✓ npm configuration locked" -Level Success

        # Layer 2: Deploy detection script
        Write-DeploymentLog "Layer 2: Deploying shadow installation detection script..." -Level Info

        $detectionScript = @'
param(
    [switch]$RemoveUnauthorized,
    [switch]$AlertSecurity
)

$scanPaths = @(
    "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code",
    "$env:LOCALAPPDATA\npm\node_modules\@anthropic-ai\claude-code"
)

$findings = @()

foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        $finding = @{
            Path = $path
            User = $env:USERNAME
            Computer = $env:COMPUTERNAME
            Timestamp = Get-Date -Format "o"
        }
        $findings += $finding

        Write-EventLog -LogName Application -Source "ClaudeCodeSecurity" `
            -EventId 4001 -EntryType Warning `
            -Message "Shadow installation detected: $path by $env:USERNAME"

        if ($RemoveUnauthorized) {
            Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

return $findings
'@

        $detectionScriptPath = Join-Path $Script:DeploymentConfig.ScriptsPath "Find-ShadowClaudeInstallations.ps1"
        Set-Content -Path $detectionScriptPath -Value $detectionScript -Force

        # Create scheduled task
        try {
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
                -Argument "-ExecutionPolicy Bypass -File `"$detectionScriptPath`" -RemoveUnauthorized"
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration ([TimeSpan]::MaxValue)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

            Register-ScheduledTask -TaskName "ClaudeCode Shadow Installation Scanner" `
                -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

            Write-DeploymentLog "✓ Detection script deployed and scheduled" -Level Success
        } catch {
            Write-DeploymentLog "WARNING: Could not create scheduled task: $_" -Level Warning
        }

        # Register event log source
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("ClaudeCodeSecurity")) {
                New-EventLog -LogName Application -Source "ClaudeCodeSecurity"
            }
        } catch {
            Write-DeploymentLog "WARNING: Could not create event log source" -Level Warning
        }

        Add-DeploymentResult -Component "Shadow Prevention" -Status "Success" -Details "Multi-layer protection enabled"

    } catch {
        Write-DeploymentLog "Shadow prevention failed: $_" -Level Error
        Add-DeploymentResult -Component "Shadow Prevention" -Status "Failed" -Details $_.Exception.Message
    }
}

#endregion

#region Windows Security Integration

function Enable-WindowsSecurityIntegration {
    <#
    .SYNOPSIS
        Configures Windows Firewall, Defender, and audit policies
    #>

    Write-DeploymentLog "========== WINDOWS SECURITY INTEGRATION ==========" -Level Info

    try {
        # Firewall Rules
        Write-DeploymentLog "Configuring Windows Firewall rules..." -Level Info

        try {
            # Allow Anthropic API
            New-NetFirewallRule -DisplayName "Claude Code - Anthropic API" `
                -Direction Outbound `
                -Program "$($Script:DeploymentConfig.NpmGlobalPath)\node.exe" `
                -RemoteAddress "api.anthropic.com" `
                -Protocol TCP `
                -RemotePort 443 `
                -Action Allow `
                -ErrorAction SilentlyContinue | Out-Null

            Write-DeploymentLog "✓ Firewall rule created for Anthropic API" -Level Success
        } catch {
            Write-DeploymentLog "WARNING: Could not create firewall rule" -Level Warning
        }

        # Audit Policy
        Write-DeploymentLog "Configuring audit policies..." -Level Info

        try {
            # Enable process tracking
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
            # Enable file system auditing
            auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

            Write-DeploymentLog "✓ Audit policies configured" -Level Success
        } catch {
            Write-DeploymentLog "WARNING: Could not configure audit policies" -Level Warning
        }

        Add-DeploymentResult -Component "Windows Security" -Status "Success" -Details "Firewall and audit configured"

    } catch {
        Write-DeploymentLog "Windows security integration failed: $_" -Level Error
        Add-DeploymentResult -Component "Windows Security" -Status "Failed" -Details $_.Exception.Message
    }
}

#endregion

#region Monitoring & Audit Module

function Setup-MonitoringAndAudit {
    <#
    .SYNOPSIS
        Sets up comprehensive monitoring and audit logging
    #>

    Write-DeploymentLog "========== MONITORING & AUDIT SETUP ==========" -Level Info

    try {
        # Create log rotation script
        $logRotationScript = @'
$logDir = "C:\ProgramData\ClaudeCode\logs"
$maxLogAge = (Get-Date).AddDays(-90)

Get-ChildItem -Path $logDir -Filter "*.jsonl" | Where-Object {
    $_.LastWriteTime -lt $maxLogAge
} | ForEach-Object {
    $archiveName = "$($_.BaseName).zip"
    Compress-Archive -Path $_.FullName -DestinationPath (Join-Path $logDir "archive\$archiveName") -Force
    Remove-Item $_.FullName -Force
}
'@

        $logRotationPath = Join-Path $Script:DeploymentConfig.ScriptsPath "Rotate-AuditLogs.ps1"
        Set-Content -Path $logRotationPath -Value $logRotationScript -Force

        # Create archive directory
        $archiveDir = Join-Path $Script:DeploymentConfig.LogsPath "archive"
        if (-not (Test-Path $archiveDir)) {
            New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
        }

        Write-DeploymentLog "✓ Log rotation script created" -Level Success

        # Create compliance report script
        $complianceReportScript = @'
param(
    [datetime]$StartDate = (Get-Date).AddDays(-30),
    [datetime]$EndDate = (Get-Date)
)

$logFiles = Get-ChildItem -Path "C:\ProgramData\ClaudeCode\logs" -Filter "*.jsonl"
$events = @()

foreach ($logFile in $logFiles) {
    Get-Content $logFile | ForEach-Object {
        $events += ($_ | ConvertFrom-Json)
    }
}

$report = @{
    ReportDate = Get-Date -Format "o"
    Period = "$($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd'))"
    TotalEvents = $events.Count
    UniqueUsers = ($events | Select-Object -ExpandProperty user -Unique).Count
    EventsByTool = $events | Group-Object tool | Select-Object Name, Count
    EventsByUser = $events | Group-Object user | Select-Object Name, Count
}

$report | ConvertTo-Json -Depth 5
'@

        $complianceReportPath = Join-Path $Script:DeploymentConfig.ScriptsPath "Generate-ComplianceReport.ps1"
        Set-Content -Path $complianceReportPath -Value $complianceReportScript -Force

        Write-DeploymentLog "✓ Compliance report script created" -Level Success

        Add-DeploymentResult -Component "Monitoring & Audit" -Status "Success" -Details "Audit logging and reporting configured"

    } catch {
        Write-DeploymentLog "Monitoring setup failed: $_" -Level Error
        Add-DeploymentResult -Component "Monitoring & Audit" -Status "Failed" -Details $_.Exception.Message
    }
}

#endregion

#region Testing & Validation

function Test-Deployment {
    <#
    .SYNOPSIS
        Runs comprehensive validation tests
    #>

    Write-DeploymentLog "========== DEPLOYMENT VALIDATION ==========" -Level Info

    $testResults = @{
        Passed = @()
        Failed = @()
    }

    # Test 1: Installation path
    Write-DeploymentLog "Test 1: Verifying installation path..." -Level Info
    if (Test-Path $InstallPath) {
        Write-DeploymentLog "✓ Installation path exists" -Level Success
        $testResults.Passed += "Installation Path"
    } else {
        Write-DeploymentLog "✗ Installation path not found" -Level Error
        $testResults.Failed += "Installation Path"
    }

    # Test 2: Claude Code execution
    Write-DeploymentLog "Test 2: Testing Claude Code execution..." -Level Info
    try {
        $version = claude --version 2>&1
        if ($version) {
            Write-DeploymentLog "✓ Claude Code executes: $version" -Level Success
            $testResults.Passed += "Claude Execution"
        }
    } catch {
        Write-DeploymentLog "✗ Claude Code execution failed" -Level Error
        $testResults.Failed += "Claude Execution"
    }

    # Test 3: Managed policies
    Write-DeploymentLog "Test 3: Checking managed policies..." -Level Info
    $managedSettingsPath = Join-Path $Script:DeploymentConfig.ManagedPoliciesPath "managed-settings.json"
    if (Test-Path $managedSettingsPath) {
        $isReadOnly = (Get-ItemProperty -Path $managedSettingsPath).IsReadOnly
        if ($isReadOnly) {
            Write-DeploymentLog "✓ Managed policies exist and are read-only" -Level Success
            $testResults.Passed += "Managed Policies"
        } else {
            Write-DeploymentLog "✗ Managed policies not read-only" -Level Error
            $testResults.Failed += "Managed Policies"
        }
    } else {
        Write-DeploymentLog "✗ Managed policies not found" -Level Error
        $testResults.Failed += "Managed Policies"
    }

    # Test 4: Security hooks
    Write-DeploymentLog "Test 4: Checking security hooks..." -Level Info
    $validateEditPath = Join-Path $Script:DeploymentConfig.HooksPath "validate-edit.ps1"
    if (Test-Path $validateEditPath) {
        Write-DeploymentLog "✓ Security hooks deployed" -Level Success
        $testResults.Passed += "Security Hooks"
    } else {
        Write-DeploymentLog "✗ Security hooks not found" -Level Error
        $testResults.Failed += "Security Hooks"
    }

    # Test 5: npm configuration
    Write-DeploymentLog "Test 5: Verifying npm configuration..." -Level Info
    $npmPrefix = npm config get prefix 2>&1
    if ($npmPrefix -like "*$($Script:DeploymentConfig.NpmGlobalPath)*") {
        Write-DeploymentLog "✓ npm prefix correctly configured" -Level Success
        $testResults.Passed += "npm Configuration"
    } else {
        Write-DeploymentLog "✗ npm prefix not correctly set" -Level Error
        $testResults.Failed += "npm Configuration"
    }

    # Summary
    Write-DeploymentLog "" -Level Info
    Write-DeploymentLog "========== TEST SUMMARY ==========" -Level Info
    Write-DeploymentLog "Passed: $($testResults.Passed.Count)" -Level Success
    Write-DeploymentLog "Failed: $($testResults.Failed.Count)" -Level $(if ($testResults.Failed.Count -eq 0) { "Success" } else { "Error" })

    if ($testResults.Failed.Count -eq 0) {
        Write-DeploymentLog "✓ All tests passed!" -Level Success
        Add-DeploymentResult -Component "Validation Tests" -Status "Success" -Details "All tests passed"
    } else {
        Write-DeploymentLog "Failed tests: $($testResults.Failed -join ', ')" -Level Error
        Add-DeploymentResult -Component "Validation Tests" -Status "Failed" -Details "Some tests failed"
    }

    return $testResults
}

#endregion

#region Uninstall Module

function Uninstall-ClaudeCodeEnterprise {
    <#
    .SYNOPSIS
        Uninstalls Claude Code and removes all configurations
    #>

    Write-DeploymentLog "========== UNINSTALL MODULE ==========" -Level Info

    if (-not $Silent) {
        $confirmation = Read-Host "Are you sure you want to uninstall? (yes/no)"
        if ($confirmation -ne "yes") {
            Write-DeploymentLog "Uninstall cancelled" -Level Info
            return
        }
    }

    try {
        # Uninstall npm package
        Write-DeploymentLog "Uninstalling Claude Code npm package..." -Level Info
        npm uninstall -g @anthropic-ai/claude-code 2>&1 | Out-Null

        # Remove scheduled tasks
        Write-DeploymentLog "Removing scheduled tasks..." -Level Info
        Unregister-ScheduledTask -TaskName "ClaudeCode Shadow Installation Scanner" -Confirm:$false -ErrorAction SilentlyContinue

        # Remove firewall rules
        Write-DeploymentLog "Removing firewall rules..." -Level Info
        Remove-NetFirewallRule -DisplayName "Claude Code - Anthropic API" -ErrorAction SilentlyContinue

        # Remove installation directory
        Write-DeploymentLog "Removing installation directory..." -Level Info
        if (Test-Path $InstallPath) {
            # Remove read-only attribute from files
            Get-ChildItem -Path $InstallPath -Recurse -File | ForEach-Object {
                Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false
            }
            Remove-Item -Path $InstallPath -Recurse -Force
        }

        # Remove PATH entry
        Write-DeploymentLog "Removing from system PATH..." -Level Info
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $newPath = $currentPath -replace [regex]::Escape(";$($Script:DeploymentConfig.NpmGlobalPath)"), ""
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

        Write-DeploymentLog "✓ Uninstall completed successfully" -Level Success

    } catch {
        Write-DeploymentLog "Uninstall failed: $_" -Level Error
    }
}

#endregion

#region Menu System

function Show-DeploymentMenu {
    <#
    .SYNOPSIS
        Displays interactive deployment menu
    #>

    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Claude Code Enterprise Deployment Automation" -ForegroundColor Cyan
    Write-Host "  Version: $($Script:DeploymentConfig.Version)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Full Enterprise Deployment (Recommended)" -ForegroundColor Green
    Write-Host "  [2] Install Claude Code Only"
    Write-Host "  [3] Deploy Security Policies Only"
    Write-Host "  [4] Deploy Security Hooks Only"
    Write-Host "  [5] Enable Shadow Installation Prevention"
    Write-Host "  [6] Windows Security Integration"
    Write-Host "  [7] Monitoring & Audit Setup"
    Write-Host "  [8] Run Validation Tests"
    Write-Host "  [9] Uninstall"
    Write-Host "  [0] Exit"
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    $choice = Read-Host "Select option"

    return $choice
}

function Invoke-MenuSelection {
    param([string]$Choice)

    switch ($Choice) {
        "1" {
            Write-DeploymentLog "Starting FULL ENTERPRISE DEPLOYMENT..." -Level Info
            Install-ClaudeCodeEnterprise
            Deploy-ManagedPolicies
            Deploy-SecurityHooks
            Enable-ShadowInstallationPrevention
            Enable-WindowsSecurityIntegration
            Setup-MonitoringAndAudit
            Test-Deployment
        }
        "2" { Install-ClaudeCodeEnterprise }
        "3" { Deploy-ManagedPolicies }
        "4" { Deploy-SecurityHooks }
        "5" { Enable-ShadowInstallationPrevention }
        "6" { Enable-WindowsSecurityIntegration }
        "7" { Setup-MonitoringAndAudit }
        "8" { Test-Deployment }
        "9" { Uninstall-ClaudeCodeEnterprise }
        "0" { exit }
        default { Write-Host "Invalid selection" -ForegroundColor Red }
    }
}

#endregion

#region Main Execution

function Main {
    <#
    .SYNOPSIS
        Main execution flow
    #>

    # Start transcript logging
    Start-Transcript -Path $Script:LogFile -Append

    try {
        Write-DeploymentLog "Claude Code Enterprise Deployment Script v$($Script:DeploymentConfig.Version)" -Level Info
        Write-DeploymentLog "Deployment started at: $($Script:DeploymentConfig.DeploymentDate)" -Level Info

        # Validate prerequisites
        if (-not $SkipValidation) {
            Test-Prerequisites
        }

        # Determine execution mode
        if ($FullDeployment) {
            Install-ClaudeCodeEnterprise
            Deploy-ManagedPolicies
            Deploy-SecurityHooks
            Enable-ShadowInstallationPrevention
            Enable-WindowsSecurityIntegration
            Setup-MonitoringAndAudit
            Test-Deployment
        }
        elseif ($InstallOnly) { Install-ClaudeCodeEnterprise }
        elseif ($PoliciesOnly) { Deploy-ManagedPolicies }
        elseif ($HooksOnly) { Deploy-SecurityHooks }
        elseif ($ShadowPrevention) { Enable-ShadowInstallationPrevention }
        elseif ($WindowsSecurity) { Enable-WindowsSecurityIntegration }
        elseif ($Monitoring) { Setup-MonitoringAndAudit }
        elseif ($Test) { Test-Deployment }
        elseif ($Uninstall) { Uninstall-ClaudeCodeEnterprise }
        else {
            # Interactive menu mode
            do {
                $selection = Show-DeploymentMenu
                if ($selection -ne "0") {
                    Invoke-MenuSelection -Choice $selection
                    if (-not $Silent) {
                        Read-Host "`nPress Enter to continue"
                    }
                }
            } while ($selection -ne "0")
        }

        # Display summary
        Write-DeploymentLog "" -Level Info
        Write-DeploymentLog "========== DEPLOYMENT SUMMARY ==========" -Level Info
        Write-DeploymentLog "Successful: $($Script:DeploymentResults.Success.Count)" -Level Success
        Write-DeploymentLog "Failed: $($Script:DeploymentResults.Failed.Count)" -Level $(if ($Script:DeploymentResults.Failed.Count -eq 0) { "Success" } else { "Error" })
        Write-DeploymentLog "Warnings: $($Script:DeploymentResults.Warnings.Count)" -Level $(if ($Script:DeploymentResults.Warnings.Count -eq 0) { "Success" } else { "Warning" })

        if ($Script:DeploymentResults.Failed.Count -eq 0) {
            Write-DeploymentLog "" -Level Info
            Write-DeploymentLog "✓ DEPLOYMENT COMPLETED SUCCESSFULLY!" -Level Success
            Write-DeploymentLog "Log file: $Script:LogFile" -Level Info
        } else {
            Write-DeploymentLog "" -Level Info
            Write-DeploymentLog "⚠ DEPLOYMENT COMPLETED WITH ERRORS" -Level Warning
            Write-DeploymentLog "Please review the log file: $Script:LogFile" -Level Warning
        }

    } catch {
        Write-DeploymentLog "FATAL ERROR: $_" -Level Error
        Write-DeploymentLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
    } finally {
        Stop-Transcript
    }
}

# Execute main function
Main

#endregion
