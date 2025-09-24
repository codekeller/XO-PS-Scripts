# Get-XenOrchestraBackupReport.ps1

A PowerShell script that generates backup summary reports for Xen Orchestra by retrieving both backup job definitions and execution logs through the REST API.

## Overview

This script connects to your Xen Orchestra server to provide a complete view of your backup infrastructure. It retrieves all configured backup jobs (VM backups, metadata backups, and mirror/replication jobs) and correlates them with recent execution history to produce professional HTML reports suitable for management review or operational monitoring.

## Key Features

- **Comprehensive Coverage**: Retrieves all backup job types (VM, Metadata, Mirror/Replication)
- **Smart Correlation**: Matches job definitions with execution history for complete status visibility
- **Professional Reports**: Generates clean HTML reports with executive summaries and detailed logs
- **Flexible Filtering**: Customizable time ranges and status filtering (success/failure/skipped)
- **Email Integration**: Optional automated email delivery with SMTP support
- **Security**: Secure API token handling with encrypted file storage support
- **Robust Error Handling**: Retry logic, timeout handling, and comprehensive logging
- **SSL Flexibility**: Support for self-signed certificates in internal environments

## Prerequisites

- PowerShell 5.1 or higher (Windows PowerShell) or PowerShell Core 6+ (cross-platform)
- Network connectivity to your Xen Orchestra server
- Valid Xen Orchestra API token with appropriate permissions
- SMTP server access (if using email functionality)

## Quick Start

```powershell
# Basic report generation
.\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "your-api-token"

# Display help
.\Get-XenOrchestraBackupReport.ps1 -h
```

## Authentication Setup

### API Token Generation
1. Access your Xen Orchestra web interface
2. Navigate to **Settings → API**
3. Click **Create New Token**
4. Assign appropriate permissions (Only admin users can currently use the REST API)
5. Copy and securely store the generated token

### Secure Token Storage (Recommended)
Instead of using tokens directly in command lines, create encrypted token files:

```powershell
# Create encrypted token file (one-time setup)
Read-Host "Enter XO API Token" -AsSecureString | ConvertFrom-SecureString | Out-File "C:\secure\xo-token.txt"

# Use encrypted token in script
.\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiTokenFile "C:\secure\xo-token.txt"
```

**Security Note**: Encrypted token files are tied to the Windows user account and machine where created.

## Parameters

### Required Parameters
- **`-XenOrchestraUrl`**: Base URL of your Xen Orchestra server (e.g., "https://xo.company.com")

### Authentication (Choose One)
- **`-ApiToken`**: API token as string parameter
- **`-ApiTokenFile`**: Path to file containing encrypted API token

### Report Configuration
- **`-TimeSpanHours`**: Hours back to query for backup jobs (1-168, default: 24)
- **`-IncludeSuccess`**: Include successful backups (default: $true)
- **`-IncludeFailures`**: Include failed backups (default: $true)  
- **`-IncludeSkipped`**: Include skipped backups (default: $false)

### Output Options
- **`-OutputPath`**: Path to save HTML report file
- **`-LogFile`**: Path for script execution log

### Connection Settings
- **`-MaxRetries`**: API call retry attempts (default: 3)
- **`-TimeoutSeconds`**: API timeout in seconds (default: 30)
- **`-SkipCertificateCheck`**: Skip SSL certificate validation

### Email Settings
- **`-SendEmail`**: Enable email delivery
- **`-SmtpServer`**: SMTP server hostname
- **`-SmtpPort`**: SMTP port (default: 25)
- **`-SmtpUseSsl`**: Use SSL/TLS (default: $false)
- **`-EmailFrom`**: Sender email address
- **`-EmailTo`**: Recipient email address(es)
- **`-EmailSubject`**: Email subject line
- **`-SmtpCredential`**: SMTP authentication credentials

### Debugging
- **`-EnableDebugLogging`**: Enable verbose debug output
- **`-Help` / `-h`**: Display help information

## Usage Examples

### Basic Report to File
```powershell
.\Get-XenOrchestraBackupReport.ps1 `
    -XenOrchestraUrl "https://xo.company.com" `
    -ApiTokenFile "C:\secure\xo-token.txt" `
    -OutputPath "C:\Reports\backup-report-$(Get-Date -Format 'yyyy-MM-dd').html"
```

### Extended Time Range with All Job Types
```powershell
.\Get-XenOrchestraBackupReport.ps1 `
    -XenOrchestraUrl "https://xo.company.com" `
    -ApiToken "your-token" `
    -TimeSpanHours 48 `
    -IncludeSkipped $true `
    -OutputPath "C:\Reports\extended-backup-report.html"
```

### Daily Email Report
```powershell
.\Get-XenOrchestraBackupReport.ps1 `
    -XenOrchestraUrl "https://xo.company.com" `
    -ApiTokenFile "C:\secure\xo-token.txt" `
    -SendEmail `
    -SmtpServer "mail.company.com" `
    -EmailFrom "xo-reports@company.com" `
    -EmailTo @("admin@company.com", "backup-team@company.com") `
    -EmailSubject "Daily XO Backup Report - $(Get-Date -Format 'yyyy-MM-dd')"
```

### Troubleshooting Mode
```powershell
.\Get-XenOrchestraBackupReport.ps1 `
    -XenOrchestraUrl "https://xo.company.com" `
    -ApiToken "your-token" `
    -TimeSpanHours 72 `
    -IncludeSkipped $true `
    -EnableDebugLogging `
    -LogFile "debug-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" `
    -SkipCertificateCheck
```

### Self-Signed Certificate Environment
```powershell
.\Get-XenOrchestraBackupReport.ps1 `
    -XenOrchestraUrl "https://xo.internal.company.com" `
    -ApiToken "your-token" `
    -SkipCertificateCheck `
    -OutputPath "backup-status.html"
```

## Report Output

The script generates a comprehensive HTML report containing:

### Executive Summary
- Total defined backup jobs
- Jobs executed in timeframe
- Success/failure/skipped counts
- Visual status indicators

### Job Definitions Overview
- All configured backup jobs grouped by type
- Current execution status for each job
- Last execution time and result
- Visual grid layout for easy scanning

### Detailed Execution Logs
- Chronological list of all backup executions
- Start/end times and duration
- Error messages for failed jobs
- Filterable by status type

## Scheduling Automation

### Windows Task Scheduler
Create a scheduled task to run daily reports:

```powershell
# Create scheduled task for daily reports
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"C:\Scripts\Get-XenOrchestraBackupReport.ps1`" -XenOrchestraUrl `"https://xo.company.com`" -ApiTokenFile `"C:\secure\xo-token.txt`" -SendEmail -SmtpServer `"mail.company.com`" -EmailFrom `"xo-reports@company.com`" -EmailTo `"admin@company.com`""

$Trigger = New-ScheduledTaskTrigger -Daily -At "08:00"

$Principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\ServiceAccount" -LogonType Password

Register-ScheduledTask -TaskName "XO Daily Backup Report" -Action $Action -Trigger $Trigger -Principal $Principal
```

### Linux/macOS Cron
Add to crontab for daily execution:
```bash
# Daily at 8:00 AM
0 8 * * * /usr/bin/pwsh -File "/opt/scripts/Get-XenOrchestraBackupReport.ps1" -XenOrchestraUrl "https://xo.company.com" -ApiTokenFile "/secure/xo-token.txt" -SendEmail -SmtpServer "mail.company.com" -EmailFrom "xo-reports@company.com" -EmailTo "admin@company.com"
```

## Troubleshooting

### Authentication Issues
```
Error: Authentication failed. Please check your API token.
Solution: Verify token is valid, not expired, and has sufficient permissions
```

### SSL Certificate Errors
```
Error: SSL connection could not be established
Solution: Add -SkipCertificateCheck parameter for self-signed certificates
```

### No Backup Data Found
```
Issue: Report shows no backup jobs or execution data
Solutions:
- Increase -TimeSpanHours value (try 48 or 72)
- Set -IncludeSkipped $true to see all execution attempts
- Verify backup jobs exist and have run recently
- Check XO server logs for API access issues
```

### Email Delivery Failures
```
Issue: Email reports not being delivered
Solutions:
- Verify SMTP server settings and network connectivity
- Check authentication credentials
- Test with simple Send-MailMessage command first
- Review firewall/security group settings
```

### Performance Issues
```
Issue: Script runs slowly or times out
Solutions:
- Increase -TimeoutSeconds parameter
- Reduce -TimeSpanHours to query less data
- Check network latency to XO server
- Use -MaxRetries to handle intermittent issues
```

### Debug Mode
For detailed troubleshooting, enable debug logging:
```powershell
.\Get-XenOrchestraBackupReport.ps1 -EnableDebugLogging -LogFile "debug.log" [other parameters]
```

## API Requirements

### API Endpoints Used
- `/rest/v0/backup/jobs/vm` - VM backup job definitions
- `/rest/v0/backup/jobs/metadata` - Metadata backup job definitions  
- `/rest/v0/backup/jobs/mirror` - Mirror/replication job definitions
- `/rest/v0/backup/logs/` - Backup execution logs with filtering
- `/rest/v0/vms` - Authentication test endpoint

## Error Codes

| Exit Code | Description |
|-----------|-------------|
| 0 | Success |
| 1 | Authentication failure |
| 2 | Network/connection error |
| 3 | Invalid parameters |
| 4 | File I/O error |
| 5 | Email delivery failure |

## Version History

### v2.0.0
- Added backup job definition retrieval and correlation
- Enhanced HTML report formatting with executive summary
- Implemented parameter sets for help functionality
- Added encrypted token file support
- Improved error handling and retry logic
- Added email delivery capabilities

### v1.0.0
- Initial release with basic backup log retrieval
- Simple HTML report generation
- Basic authentication support

## Support

For issues, questions, or feature requests, please refer to the main repository documentation or create an issue in the project repository.
