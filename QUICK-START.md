# Claude Code Enterprise Deployment - Quick Start Guide

## 🚀 5-Minute Deployment

### Step 1: Verify Prerequisites
```powershell
# Check Node.js and npm
node --version
npm --version

# Check PowerShell version
$PSVersionTable.PSVersion
```

### Step 2: Run Deployment Script as Administrator
```powershell
# Option A: Interactive Menu (Recommended)
.\Deploy-ClaudeCode-Enterprise.ps1

# Option B: Full Automated Deployment
.\Deploy-ClaudeCode-Enterprise.ps1 -FullDeployment
```

### Step 3: Verify Installation
```powershell
# Test Claude Code
claude --version

# Run validation tests
.\Deploy-ClaudeCode-Enterprise.ps1 -Test
```

## ✅ What Gets Deployed

| Component | Location | Description |
|-----------|----------|-------------|
| **Claude Code** | `C:\ProgramData\ClaudeCode\npm-global` | Main installation |
| **Policies** | `C:\ProgramData\ClaudeCode\managed-policies\` | Security policies (read-only) |
| **Hooks** | `C:\ProgramData\ClaudeCode\hooks\` | Security validation scripts |
| **Logs** | `C:\ProgramData\ClaudeCode\logs\` | Audit logs and deployment logs |
| **Scripts** | `C:\ProgramData\ClaudeCode\scripts\` | Utility and monitoring scripts |

## 🔐 Security Features Enabled

- ✅ Installation in non-writable location
- ✅ Managed policies (highest precedence, read-only)
- ✅ PreToolUse hooks (blocks sensitive file access)
- ✅ PostToolUse hooks (audit logging)
- ✅ Shadow installation detection (every 4 hours)
- ✅ Windows Firewall rules
- ✅ Audit policy configuration
- ✅ Event log monitoring

## 📋 Common Commands

### Deploy Specific Components

```powershell
# Install only
.\Deploy-ClaudeCode-Enterprise.ps1 -InstallOnly

# Security policies only
.\Deploy-ClaudeCode-Enterprise.ps1 -PoliciesOnly

# Security hooks only
.\Deploy-ClaudeCode-Enterprise.ps1 -HooksOnly

# Shadow prevention only
.\Deploy-ClaudeCode-Enterprise.ps1 -ShadowPrevention

# Monitoring setup only
.\Deploy-ClaudeCode-Enterprise.ps1 -Monitoring
```

### Testing & Validation

```powershell
# Run all validation tests
.\Deploy-ClaudeCode-Enterprise.ps1 -Test

# Check Claude version
claude --version

# Verify managed policies
Get-Content "C:\ProgramData\ClaudeCode\managed-policies\managed-settings.json"

# Check security hooks
Get-ChildItem "C:\ProgramData\ClaudeCode\hooks\"

# View deployment log
Get-Content "C:\ProgramData\ClaudeCode\logs\deployment-*.log" -Tail 50
```

### Monitoring & Audit

```powershell
# View today's audit log
Get-Content "C:\ProgramData\ClaudeCode\logs\audit-$(Get-Date -Format 'yyyy-MM-dd').jsonl"

# Check for shadow installations
C:\ProgramData\ClaudeCode\scripts\Find-ShadowClaudeInstallations.ps1

# Generate compliance report
C:\ProgramData\ClaudeCode\scripts\Generate-ComplianceReport.ps1

# View security events
Get-EventLog -LogName Application -Source "ClaudeCodeSecurity" -Newest 10
```

### Maintenance

```powershell
# Rotate old logs
C:\ProgramData\ClaudeCode\scripts\Rotate-AuditLogs.ps1

# Re-deploy policies after customization
.\Deploy-ClaudeCode-Enterprise.ps1 -PoliciesOnly

# Re-deploy hooks after updates
.\Deploy-ClaudeCode-Enterprise.ps1 -HooksOnly
```

### Uninstall

```powershell
# Complete uninstall
.\Deploy-ClaudeCode-Enterprise.ps1 -Uninstall
```

## 🛠️ Customization

### Add Custom File Patterns to Block

1. Edit: `C:\ProgramData\ClaudeCode\hooks\sensitive-files.json`
2. Add your patterns:
```json
{
  "extensions": ["*.secret", "*.custom"],
  "filenames": ["myfile.txt"],
  "paths": ["**/private/*"]
}
```
3. Save (no need to redeploy)

### Add Custom Deny Rules

1. Edit: `C:\ProgramData\ClaudeCode\managed-policies\managed-settings.json`
2. Make file writable: `Set-ItemProperty -Name IsReadOnly -Value $false`
3. Add rules to `permissions.deny` array
4. Save and lock: `Set-ItemProperty -Name IsReadOnly -Value $true`
5. Restart Claude Code sessions

## 🔍 Troubleshooting

### Issue: Claude not found after install
```powershell
# Refresh environment
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

# Or restart PowerShell
```

### Issue: Hook not blocking sensitive files
```powershell
# Check hook exists
Test-Path "C:\ProgramData\ClaudeCode\hooks\validate-edit.ps1"

# Test hook manually
$testInput = '{"parameters":{"file_path":".env"},"tool":"Edit"}'
powershell -File "C:\ProgramData\ClaudeCode\hooks\validate-edit.ps1" -CLAUDE_HOOK_INPUT $testInput
# Should output block message and exit code 2
```

### Issue: Shadow detection not running
```powershell
# Check scheduled task
Get-ScheduledTask -TaskName "ClaudeCode*"

# Run manually
C:\ProgramData\ClaudeCode\scripts\Find-ShadowClaudeInstallations.ps1

# Run with remediation
C:\ProgramData\ClaudeCode\scripts\Find-ShadowClaudeInstallations.ps1 -RemoveUnauthorized
```

### Issue: Audit logs not created
```powershell
# Check logs directory
Test-Path "C:\ProgramData\ClaudeCode\logs"

# Check audit hook
Test-Path "C:\ProgramData\ClaudeCode\hooks\audit-log.ps1"

# Test manually (run a Claude command and check)
claude --version
Get-ChildItem "C:\ProgramData\ClaudeCode\logs\audit-*.jsonl"
```

## 📊 Verification Checklist

After deployment, verify:

- [ ] Claude Code executes: `claude --version`
- [ ] Managed policies exist: `C:\ProgramData\ClaudeCode\managed-policies\managed-settings.json`
- [ ] Policies are read-only: `(Get-ItemProperty "...\managed-settings.json").IsReadOnly`
- [ ] Hooks exist: `Get-ChildItem "C:\ProgramData\ClaudeCode\hooks"`
- [ ] Scheduled task created: `Get-ScheduledTask -TaskName "ClaudeCode*"`
- [ ] Firewall rule exists: `Get-NetFirewallRule -DisplayName "Claude Code*"`
- [ ] Event source registered: `[System.Diagnostics.EventLog]::SourceExists("ClaudeCodeSecurity")`
- [ ] npm prefix correct: `npm config get prefix` (should show ProgramData path)

## 🎯 Testing the Security

### Test 1: Try to edit .env file
```powershell
# This should be BLOCKED by hooks
claude "Edit .env file and add API_KEY=test"
# Expected: "SECURITY BLOCK: Cannot edit sensitive file"
```

### Test 2: Try to edit Windows system file
```powershell
# This should be BLOCKED
claude "Edit C:\Windows\System32\notepad.exe"
# Expected: "SECURITY BLOCK: Cannot edit system directory"
```

### Test 3: Try dangerous bash command
```powershell
# This should be BLOCKED or require confirmation
claude "Run: rm -rf /"
# Expected: "SECURITY BLOCK: Dangerous command detected"
```

### Test 4: Check audit logging
```powershell
# Run a safe command
claude --version

# Verify audit log created
Get-Content "C:\ProgramData\ClaudeCode\logs\audit-$(Get-Date -Format 'yyyy-MM-dd').jsonl" | Select-Object -Last 1
# Expected: JSON entry with timestamp, user, tool, etc.
```

### Test 5: Try shadow installation
```powershell
# Try to install in AppData (this should fail or be detected)
npm install -g @anthropic-ai/claude-code --prefix=%APPDATA%\npm

# Check if detected
C:\ProgramData\ClaudeCode\scripts\Find-ShadowClaudeInstallations.ps1
# Expected: Detection and/or blocking
```

## 📞 Support

- **Logs**: `C:\ProgramData\ClaudeCode\logs\`
- **Events**: Application Event Log (Source: ClaudeCodeSecurity)
- **Documentation**: See `Deploy-ClaudeCode-Enterprise-README.md`
- **Full Guide**: See `claude-code-windows-enterprise-security-guide.md`

---

**Quick Start Guide v2.0**
**Last Updated**: October 2025
