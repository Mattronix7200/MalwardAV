<p align="center"><img width="70%" height="70%" alt="logo" src="https://github.com/user-attachments/assets/ab0706d5-77be-4133-bc6d-2791f27f76ed" /></p>

#
Malward is a free, second-opinion antivirus scanner — it runs alongside your primary security software to catch what might have slipped past it. You don't need to uninstall anything, as it is designed not to conflict with other security solutions. The program is lightweight and effective: the scanner engine utilizes local signature databases and cloud analysis, keeping system resource usage to a minimum while maximizing detection rates.

### Main Protection Modules:
- Real-Time Protection – continuous monitoring and threat analysis in real time.
- Network Protection – blocking malicious domains and unwanted network traffic.
- Integrated Firewall Module (based on Windows Firewall) – process-level connection control.
- System Component Protection – detecting and blocking suspicious system behaviors.
- Backup – securing the user's most critical data.

<img width="1058" height="598" alt="image" src="https://github.com/user-attachments/assets/483ddd90-0a0c-4367-abb7-cb1f01d9af5a" />

### Important Product Information
The program features real-time protection mechanisms that can be enabled. However, these protections are not tied to deep system integration, the so-called **kernel driver**, which would grant the program direct access to block threats in real time. The program uses all available system methods to maintain the highest possible level of security, although full protection is not guaranteed. It is best used in combination with another security suite, such as Windows Defender. The cloud analysis system scans files by sending them to our analysis server, which utilizes four scanning engines to increase coverage and detection. The uploaded file is analyzed and immediately deleted after the analysis is complete. A version of the program without protection mechanisms and additional tools is also available, offering on-demand scanning only.


## Table of Contents

- [System Requirements](#system-requirements)
- [Portable Command Tool Utility](#portable-command-tool-utility)
  - [Quick start](#quick-start)
  - [Scan modes](#scan-modes)
  - [Detection and scanning switches](#detection-and-scanning-switches)
  - [Threat handling](#threat-handling)
  - [File-extension filters](#file-extension-filters)
  - [Quarantine and exclusions](#quarantine-and-exclusions)
  - [VPS Info](#vps-info)
- [License](#license)
- [Download](#download)

## System Requirements

| Element | Requirement |
|---|---|
| OS | Windows 10 or Windows 11, **64-bit only** |
| Disk | **2 GB** |
| Memory | 1 GB |
| Network | Connection to the update server |
| Environment | **.NET SDK 8.0** |


## Portable Command Tool Utility   

<p align="center">
  <img width="1079" height="818" alt="image" src="https://github.com/user-attachments/assets/c8c9954a-24ef-483f-a137-51649b02fbe1" />
</p>

**malcsm.exe** is a portable command-line antivirus scanner for Windows. It is included with the standard Malward installation and is also available in the standalone ZIP package. You can run it directly from any folder — no separate installation is required. It provides local malware detection, optional cloud verification, heuristic analysis, archive scanning, quarantine management, exclusions, database updates, and detailed scan reports.

## Quick start

Open Command Prompt or PowerShell in the folder containing `malcsm.exe`.

```powershell
.\malcsm.exe
```

## Scan modes

| Command | Description |
| --- | --- |
| `/scan /q` or `/scan --quick` | Quick scan of common infection locations |
| `/scan /f` or `/scan --full` | Full scan of all fixed drives |
| `/scan "<path>"` | Scan one or more files or folders |
| `/help scan` | Display the complete scan help |

## Detection and scanning switches

| Switch | Description | Default |
| --- | --- | --- |
| `/cs on\|off` | Enable or disable cloud scanning | On |
| `/cv on\|off` | Enable or disable cloud verification of detections | On |
| `/cc on\|off` | Use the cloud cache for known files | On |
| `/ss on\|off` | Skip Microsoft-signed files | On |
| `/m on\|off` | Scan running processes in memory | Off |
| `/a on\|off` | Scan files inside supported archives | Off |
| `/h on\|off` | Enable heuristic analysis | Off |
| `--offline` | Disable all cloud-based scanning layers | — |
| `/t <number>` | Set the number of parallel scanning threads | CPU core count |
| `/cpu <percent>` | Limit processor usage during the scan | 100 |
| `/mfs <MB>` | Set the maximum scanned file size; `0` means max. server limit| 100 MB |
| `/mct <seconds>` | Set the cloud-verdict wait time | 30 seconds |
| `/mut <seconds>` | Set the per-file upload time limit | 60 seconds |
| `/amfs <MB>` | Set the maximum archive size; `0` means no limit | 250 MB |
| `/amn <number>` | Set the maximum archive nesting depth | 5 |
| `/log` | Save the scan report to the Desktop automatically | Off |

## Threat handling

| Switch | Description |
| --- | --- |
| `/auto` or `--autofix` | Repair detected threats automatically |
| `/fix 1` or `--fix-quar` | Move detected items to quarantine |
| `/fix 2` or `--fix-del` | Delete detected items |
| `/fix 3` or `--fix-ask` | Ask what to do after the scan |
| `/fix 4` or `--fix-ignore` | Report detections only; do not modify files |
| `/afix 1` | Remove an infected file from an archive while preserving the archive |
| `/afix 2` | Delete the entire infected archive |

> Quarantine and repair actions require an elevated console. Without administrator privileges, the scanner runs in detect-only mode.

## File-extension filters

| Switch | Description |
| --- | --- |
| `/ext 0` | Scan common executable extensions only |
| `/ext 1` | Scan all file extensions |
| `/ext {exe,msi,zip}` | Scan only the specified extensions |
| `/ext 2 {log,tmp}` | Scan everything except the specified extensions |

## Quarantine and exclusions

```powershell
# List quarantined items
.\malcsm.exe /quarmng /s

# View details of one quarantine item
.\malcsm.exe /quarmng /v <id>

# Restore an item to its original location
.\malcsm.exe /quarmng /rvt <id>

# Add a file or folder exclusion
.\malcsm.exe /exclusions /ea "C:\TrustedFolder"

# List saved exclusions
.\malcsm.exe /exclusions /ev
```

Run `.\malcsm.exe /help` to display all commands, or use `/help scan`, `/help quarmng`, `/help exclusions`, `/help update`, and `/help settings` for a specific section.

## VPS Info

To view the latest published database versions, download the current VPS database bundle, or learn how to update it manually, visit:

https://github.com/Mattronix7200/MalwardVPS


## License

Free viewing, downloading, and modification of this source code is permitted exclusively for private, educational, and non-commercial purposes.

**Terms and Restrictions:**

1. Selling, licensing, or using this code (or its modified versions) for commercial purposes without the author's prior written consent is strictly prohibited.
2. Publishing modified versions under a different brand/product as a proprietary commercial solution without the author's consent is strictly prohibited.
3. Any modified versions shared publicly must include a notice acknowledging the original author and must be distributed under this license.

The software is provided "AS IS", without any warranty of any kind.

## Download

Version: 1.0.0. Released: 04.11.2026.

https://github.com/Mattronix7200/MalwardAV/releases/tag/1.0.0

