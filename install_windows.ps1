# GuardianWall Windows Installation Script
# This script creates a Scheduled Task to run GuardianWall at startup with highest privileges

param(
    [string]$ScriptPath = $PSScriptRoot
)

Write-Host "GuardianWall Windows Installer" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Install Python if not present (assuming it's installed, but you can add logic here)
# For simplicity, we'll assume Python 3 is installed

# Copy the main script to a system location
$InstallPath = "$env:ProgramFiles\GuardianWall"
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force
}
Copy-Item "$ScriptPath\guardianwall_full.py" "$InstallPath\guardianwall_full.py"

# Install Python dependencies
& python -m pip install psutil

# Create Scheduled Task for auto-start
$TaskName = "GuardianWall Firewall"
$TaskAction = New-ScheduledTaskAction -Execute "python.exe" -Argument "$InstallPath\guardianwall_full.py" -WorkingDirectory $InstallPath
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Remove existing task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Register the new task
Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Description "GuardianWall Host-Based Firewall Service"

# Start the task immediately
Start-ScheduledTask -TaskName $TaskName

Write-Host "GuardianWall has been installed and started as a Scheduled Task." -ForegroundColor Green
Write-Host "It will automatically start on boot with highest privileges." -ForegroundColor Green
Write-Host ""
Write-Host "To check status: Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Yellow
Write-Host "To view logs: Check $InstallPath\guardianwall.log" -ForegroundColor Yellow
Write-Host "To stop: Stop-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Yellow
Write-Host "To uninstall: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:$false; Remove-Item '$InstallPath' -Recurse -Force" -ForegroundColor Yellow
