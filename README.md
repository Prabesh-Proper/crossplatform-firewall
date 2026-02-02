# GuardianWall - Cross-Platform Host-Based Firewall

A production-ready, enterprise-grade host-based firewall system that actively enforces security policies using native OS firewall APIs. Designed for both Windows and Linux environments.

## Features

- **Cross-Platform Compatibility**: Works on Windows 10/11 and Linux (Ubuntu/Debian/Kali)
- **Active Enforcement**: Uses Windows Firewall (WFP) on Windows and nftables/iptables on Linux
- **Default Deny Policy**: Blocks all inbound traffic by default
- **Allow Listed Ports**: Permits traffic only on specified safe ports (configurable)
- **Connection State Awareness**: Allows established and related connections
- **Loopback Traffic**: Permits local interface communication
- **Auto-Threat Detection**: Automatically identifies and blocks malicious IPs based on:
  - Rapid connection attempts
  - Port scanning behavior
  - Brute-force login attempts
  - High-frequency suspicious requests
- **Dynamic Blocking**: Temporarily blocks abusive IPs with configurable duration
- **Comprehensive Logging**: Records all firewall events to `guardianwall.log`
- **Persistent Service**: Runs as a background service that auto-starts on boot
- **CLI Management**: Simple commands to view blocked IPs and manage the firewall

## Architecture

GuardianWall consists of three main components:

1. **Python Control Layer** (`guardianwall_full.py`): Intelligence engine that monitors traffic, detects threats, and manages firewall rules
2. **OS Firewall Integration**: Uses native firewall APIs for rule enforcement
3. **Service Persistence**: Systemd service on Linux, Scheduled Task on Windows

## Requirements

- **Python 3.6+**
- **Administrative/Root Privileges** (required for firewall rule management)
- **psutil** Python library (automatically installed by setup scripts)

### Linux Dependencies
- nftables or iptables
- systemd

### Windows Dependencies
- Windows Firewall (built-in)
- PowerShell

## Installation

### Linux Installation

1. Clone or download the repository
2. Run the installation script with root privileges:

```bash
sudo ./install_linux.sh
```

The script will:
- Install required system packages (python3, nftables/iptables, psutil)
- Create a systemd service for GuardianWall
- Enable auto-start on boot
- Start the service immediately

### Windows Installation

1. Clone or download the repository
2. Run the PowerShell installation script as Administrator:

```powershell
.\install_windows.ps1
```

The script will:
- Install Python dependencies (psutil)
- Create a Scheduled Task that runs at startup with SYSTEM privileges
- Start the firewall service immediately

## Configuration

GuardianWall uses a JSON configuration file `guardianwall_config.json` for customization:

```json
{
  "allowed_ports": [80, 443, 22, 3389],
  "block_duration": 3600
}
```

- `allowed_ports`: List of TCP ports to allow inbound traffic on
- `block_duration`: Time in seconds to block malicious IPs (default: 1 hour)

Edit this file and restart the service to apply changes.

## Usage

### Checking Status

**Linux:**
```bash
sudo systemctl status guardianwall
```

**Windows:**
```powershell
Get-ScheduledTask -TaskName "GuardianWall Firewall"
```

### Viewing Logs

Logs are written to `guardianwall.log` in the installation directory.

**Linux:**
```bash
sudo journalctl -u guardianwall -f
```

**Windows:**
Check the log file in the installation directory (usually `C:\Program Files\GuardianWall\`).

### Viewing Currently Blocked IPs

GuardianWall does not provide a built-in CLI for this, but you can parse the log file:

```bash
grep "Blocked IP" guardianwall.log
```

### Managing the Service

**Linux:**
```bash
# Stop
sudo systemctl stop guardianwall

# Start
sudo systemctl start guardianwall

# Restart
sudo systemctl restart guardianwall
```

**Windows:**
```powershell
# Stop
Stop-ScheduledTask -TaskName "GuardianWall Firewall"

# Start
Start-ScheduledTask -TaskName "GuardianWall Firewall"
```

## Uninstallation

### Linux
```bash
sudo systemctl stop guardianwall
sudo systemctl disable guardianwall
sudo rm /etc/systemd/system/guardianwall.service
sudo systemctl daemon-reload
# Remove the GuardianWall directory if desired
```

### Windows
```powershell
Unregister-ScheduledTask -TaskName "GuardianWall Firewall" -Confirm:$false
Remove-Item "$env:ProgramFiles\GuardianWall" -Recurse -Force
```

## Security Considerations

- **Run with Minimal Privileges**: The service runs with root/SYSTEM privileges only when necessary for firewall management
- **Log Rotation**: Implement log rotation to prevent disk space exhaustion
- **Monitoring**: Regularly review logs for false positives and adjust thresholds
- **Backup Configuration**: Keep backups of `guardianwall_config.json`
- **Network Segmentation**: Use in conjunction with network-level firewalls for defense in depth

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   - Ensure Python 3 and dependencies are installed
   - Check file permissions (Linux)
   - Verify administrator privileges (Windows)

2. **Firewall Rules Not Applied**
   - Confirm the service is running with appropriate privileges
   - Check system logs for errors
   - On Linux, ensure nftables or iptables is available

3. **False Positives**
   - Adjust threat detection thresholds in the code
   - Add trusted IPs to a whitelist (future feature)

### Debug Mode

To run in debug mode (logs to console):

```bash
python3 guardianwall_full.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided as-is for educational and security research purposes. Users are responsible for ensuring compliance with local laws and regulations. The authors are not liable for any misuse or damage caused by this software.
