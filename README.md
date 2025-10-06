# Claude Code Enterprise Deployment Script

## Overview

Comprehensive PowerShell automation script for deploying Claude Code with enterprise-grade security controls on Windows environments.

## Features

✅ **Complete Automation** - One-click enterprise deployment

✅ **10 Major Modules** - Installation, policies, hooks, monitoring, testing

✅ **Interactive Menu** - User-friendly interface for selective deployment

✅ **Parameter Support** - Command-line automation for CI/CD

✅ **Comprehensive Logging** - Full audit trail with transcript logging

✅ **Validation Testing** - Built-in tests to verify deployment

✅ **Rollback Support** - Complete uninstall capability

✅ **Multi-Layer Security** - Shadow installation prevention with 7 defense layers


## Prerequisites

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1+ or PowerShell 7+
- **Privileges**: Administrator rights required
- **Dependencies**: Node.js and npm installed
- **Network**: Internet connectivity to npm registry and api.anthropic.com

## Quick Start

### Interactive Deployment (Recommended for First-Time)

```powershell
# Run as Administrator
.\Deploy-ClaudeCode-Enterprise.ps1
```

This will present an interactive menu where you can select specific components to deploy.

### Full Automated Deployment

```powershell
# Run as Administrator
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment
```

This executes all modules in sequence:
1. Installation to C:\ProgramData\ClaudeCode
2. Deployment of managed security policies
3. Deployment of security hooks
4. Shadow installation prevention
5. Windows security integration
6. Monitoring and audit setup
7. Validation testing

## Usage Scenarios

### Scenario 1: Fresh Installation

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment
```

### Scenario 2: Install Claude Code Only

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -InstallOnly
```

### Scenario 3: Deploy Security Policies Only

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -PoliciesOnly
```

### Scenario 4: Custom Installation Path

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment -InstallPath "D:\ClaudeCode"
```

### Scenario 5: Silent Deployment (No User Interaction)

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment -Silent
```

### Scenario 6: Run Validation Tests Only

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -Test
```

### Scenario 7: Uninstall Everything

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -Uninstall
```

## Available Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-FullDeployment` | Execute all modules | `-FullDeployment` |
| `-InstallOnly` | Install Claude Code only | `-InstallOnly` |
| `-PoliciesOnly` | Deploy managed policies only | `-PoliciesOnly` |
| `-HooksOnly` | Deploy security hooks only | `-HooksOnly` |
| `-ShadowPrevention` | Enable shadow installation prevention | `-ShadowPrevention` |
| `-WindowsSecurity` | Configure Windows security | `-WindowsSecurity` |
| `-Monitoring` | Setup monitoring and audit | `-Monitoring` |
| `-Test` | Run validation tests | `-Test` |
| `-Uninstall` | Uninstall and remove all configurations | `-Uninstall` |
| `-InstallPath` | Custom installation path | `-InstallPath "D:\Claude"` |
| `-Silent` | No user interaction | `-Silent` |
| `-SkipValidation` | Skip prerequisite validation | `-SkipValidation` |

## Deployment Modules

### Module 1: Installation
- Configures npm global prefix to C:\ProgramData\ClaudeCode
- Creates secure directory structure
- Sets NTFS permissions (Admins: Full, Users: Read+Execute)
- Adds to system PATH
- Installs @anthropic-ai/claude-code globally

### Module 2: Managed Policies
- Creates `managed-settings.json` with:
  - Default model: claude-sonnet-4-5
  - Default mode: plan
  - Deny rules for sensitive files (.env, .key, credentials)
  - Deny rules for system directories (C:\Windows, Program Files)
  - Ask rules for JSON, YAML, Bash commands
  - Hooks configuration (PreToolUse, PostToolUse)
- Locks policies as read-only

### Module 3: Security Hooks
- Deploys PreToolUse hooks:
  - `validate-edit.ps1` - Blocks edits to sensitive files
  - `validate-bash.ps1` - Validates dangerous bash commands
- Deploys PostToolUse hooks:
  - `audit-log.ps1` - Logs all operations to JSONL format
- Creates sensitive file patterns database
- Sets all hooks as read-only

### Module 4: Shadow Installation Prevention
- **Layer 1**: Locks npm configuration (read-only npmrc)
- **Layer 2**: Deploys shadow detection script
- **Layer 3**: Creates scheduled task (scans every 4 hours)
- **Layer 4**: Registers event log source for alerts
- **Layer 5**: Auto-remediation (removes unauthorized installs)

### Module 5: Windows Security Integration
- Configures Windows Firewall rules:
  - Allow: api.anthropic.com (443)
  - Allow: claude.ai (443)
- Enables audit policies:
  - Process Creation auditing
  - File System auditing

### Module 6: Monitoring & Audit
- Creates audit log directory with rotation
- Deploys compliance reporting script
- Configures JSONL logging format
- Sets up log archival (90-day retention)

### Module 7: Validation Testing
Runs comprehensive tests:
1. Installation path verification
2. Claude Code execution test
3. Managed policies verification
4. Security hooks validation
5. npm configuration check

### Module 8: Uninstall
- Removes npm package
- Deletes all directories
- Removes PATH entries
- Removes firewall rules
- Removes scheduled tasks
- Cleans up registry entries

## Directory Structure

After deployment, the following structure is created:

```
C:\ProgramData\ClaudeCode\
├── npm-global\              # npm global installation
│   └── node_modules\
│       └── @anthropic-ai\
│           └── claude-code\
├── managed-policies\        # Enterprise policies
│   └── managed-settings.json
├── hooks\                   # Security hooks
│   ├── validate-edit.ps1
│   ├── validate-bash.ps1
│   ├── audit-log.ps1
│   └── sensitive-files.json
├── logs\                    # Audit logs
│   ├── audit-2025-10-07.jsonl
│   ├── deployment-20251007-120000.log
│   └── archive\
├── scripts\                 # Utility scripts
│   ├── Find-ShadowClaudeInstallations.ps1
│   ├── Rotate-AuditLogs.ps1
│   └── Generate-ComplianceReport.ps1
└── npm-cache\              # npm cache directory
```

## Security Features Implemented

### 1. **Installation Security**
- Non-writable location for users
- NTFS permission hardening
- Centralized management

### 2. **Policy Enforcement**
- Managed policies with highest precedence
- Read-only policy files
- Cannot be overridden by users

### 3. **File Protection**
- Blocks access to .env, .key, .pem, credentials
- Blocks Windows system directories
- Customizable sensitive file patterns

### 4. **Command Validation**
- Validates dangerous bash commands
- Blocks destructive operations (rm -rf, format)
- Ask-before-execute for all Bash commands

### 5. **Audit Trail**
- Every operation logged to JSONL
- Includes user, timestamp, tool, success/failure
- Compliance-ready logs

### 6. **Shadow Installation Prevention**
- npm configuration lockdown
- Automated detection every 4 hours
- Auto-remediation of unauthorized installs
- Event log alerts

### 7. **Network Controls**
- Firewall rules for Anthropic API
- Optional proxy configuration support

## Logging

### Deployment Log
Location: `C:\ProgramData\ClaudeCode\logs\deployment-[timestamp].log`

Contains:
- Full transcript of deployment
- Success/failure of each module
- Warnings and errors
- Timestamps for all actions

### Audit Logs
Location: `C:\ProgramData\ClaudeCode\logs\audit-[date].jsonl`

Format: JSON Lines (one JSON object per line)

Example:
```json
{"timestamp":"2025-10-07T12:34:56","eventType":"ClaudeCodeToolUse","tool":"Edit","success":true,"user":"john.doe","computer":"WORKSTATION01"}
```

### Event Logs
- Source: ClaudeCodeSecurity
- Log: Application
- Event IDs:
  - 4001: Shadow installation detected
  - 4002: Shadow installation removed

## Testing and Validation

### Run All Tests

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -Test
```

### Tests Performed

1. **Installation Path Test** - Verifies C:\ProgramData\ClaudeCode exists
2. **Claude Execution Test** - Runs `claude --version`
3. **Managed Policies Test** - Checks policies exist and are read-only
4. **Security Hooks Test** - Verifies all hook files exist
5. **npm Configuration Test** - Validates npm prefix setting

### Expected Output

```
✓ Installation path exists
✓ Claude Code executes: 0.x.x
✓ Managed policies exist and are read-only
✓ Security hooks deployed
✓ npm prefix correctly configured

========== TEST SUMMARY ==========
Passed: 5
Failed: 0
✓ All tests passed!
```

## Troubleshooting

### Issue: "Prerequisites not met"
**Solution**: Ensure you're running as Administrator and have Node.js/npm installed

### Issue: "npm install failed"
**Solution**: Check internet connectivity and firewall settings

### Issue: "Access denied" errors
**Solution**: Run PowerShell as Administrator

### Issue: Tests fail after deployment
**Solution**:
1. Check log file: `C:\ProgramData\ClaudeCode\logs\deployment-*.log`
2. Re-run specific module: `.\Deploy-ClaudeCode-Enterprise.ps1 -[ModuleName]`
3. Try full reinstall: `.\Deploy-ClaudeCode-Enterprise.ps1 -Uninstall` then `-FullDeployment`

### Issue: Shadow detection not working
**Solution**: Verify scheduled task exists: `Get-ScheduledTask -TaskName "ClaudeCode*"`

## Multi-Machine Deployment

For deploying to multiple computers:

```powershell
# On central management server
$computers = @("PC01", "PC02", "PC03")

foreach ($computer in $computers) {
    Invoke-Command -ComputerName $computer -FilePath ".\Deploy-ClaudeCode-Enterprise.ps1" -ArgumentList "-FullDeployment", "-Silent"
}
```

## Compliance and Reporting

### Generate Compliance Report

```powershell
# Located in: C:\ProgramData\ClaudeCode\scripts\
.\Generate-ComplianceReport.ps1 -StartDate "2025-09-01" -EndDate "2025-10-01"
```

### Audit Log Rotation

Logs are automatically rotated after 90 days via scheduled task.

Manual rotation:
```powershell
.\Rotate-AuditLogs.ps1
```

## Customization

### Custom Installation Path

```powershell
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment -InstallPath "E:\CustomPath\ClaudeCode"
```

### Custom Policies

1. Edit `managed-settings.json` after deployment
2. Add custom deny/ask/allow rules
3. Re-run: `.\Deploy-ClaudeCode-Enterprise.ps1 -PoliciesOnly`

### Custom Sensitive Files

1. Edit `C:\ProgramData\ClaudeCode\hooks\sensitive-files.json`
2. Add custom extensions, filenames, or paths
3. Hooks will automatically use updated patterns

## Support and Documentation

- **Full Security Guide**: See `claude-code-windows-enterprise-security-guide.md`
- **Log Files**: `C:\ProgramData\ClaudeCode\logs\`
- **Event Logs**: Application Log (Source: ClaudeCodeSecurity)



