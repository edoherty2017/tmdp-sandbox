"""Hard-benign evaluation: legitimate admin use of non-whitelist tooling.

Addresses adversarial-review Findings 1 and 6: the flagship eval's benign set
is 100% baseline-whitelist processes (460 svchost, 4 explorer, 3 runtimebroker),
so its precision=1.000 cannot bound the deployment false-positive rate and no
benign use of powershell/net/wmic/schtasks/reg is ever tested.

This script carries its own corpus: CORPUS below is a hand-authored set of
benign Windows administrative events — the kind of powershell / cmd / reg /
schtasks / net / wmic / sc / robocopy / certutil activity a competent sysadmin
runs every day. Every process is OUTSIDE the 21-entry _BASELINE_PROCESSES
whitelist by design (most are in _SUSPICIOUS_PROCESSES), and every event is
benign, so every "malicious" verdict measured here is a false positive.

Provenance: hand-authored by the project authors on 2026-07-21 as part of the
adversarial-review remediation. NOT captured telemetry — event frequencies and
command-line phrasing were chosen by the authors, so the FP rates below are
not deployment FP-rate estimates. The eval measures whether the deployed model
can EVER say benign for a non-whitelist process.

Scores every event with the deployed model two ways — with an empty context
tuple (matching the flagship eval harness) and with a self-consistent context
stream (the corpus in authored order, k=10) — and contrasts both against the
two rule baselines the review showed the flagship eval reduces to.

Outputs FP counts/rates at p*=0.40 and p*=0.50 with Wilson 95% CIs, plus a
per-category breakdown.

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_hard_benign_eval.py
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier
from tmdp_sandbox.context_window import _BASELINE_PROCESSES
from tmdp_sandbox.event_spec import EventSpec

REPO_ROOT = Path(__file__).parent.parent
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "hard_benign_eval"

WINDOW_SIZE = 10
THRESHOLDS = (0.40, 0.50)
# The only three processes the flagship eval's label rules ever call benign.
_THREE_PROCESS_WHITELIST = frozenset({"svchost.exe", "explorer.exe", "runtimebroker.exe"})


# ---------------------------------------------------------------------------
# Hand-authored benign admin-activity corpus (this list IS the artifact).
#
# Schema matches EventSpec / load_security_scenario event dicts:
#   event_id 1 (Sysmon) or 4688 (Windows Security) process creation,
#   process_name normalized (lowercase, no path) as load_otrf_dataset produces,
#   command_line as it would appear in process-creation telemetry,
#   parent_process = spawning process, user_name = account that ran it.
# "category" is metadata for the per-category FP breakdown and is stripped
# before scoring. All events are labeled benign.
# ---------------------------------------------------------------------------

CORPUS: list[dict] = [
    # ── powershell: routine admin one-liners, signed scripts, module installs ──
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -NoLogo -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-EventLog -LogName System -Newest 50"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-EventLog -LogName Application -EntryType Error -Newest 100"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": "powershell.exe -Command \"Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20\""},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log | Measure-Object -Property Length -Sum"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'powershell.exe -Command "Get-ChildItem D:\Logs -Recurse -Filter *.log | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": "powershell.exe -Command \"Get-Service | Where-Object Status -eq 'Stopped' | Format-Table -AutoSize\""},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-Content C:\Windows\Logs\CBS\CBS.log -Tail 100"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Install-Module -Name Pester -Scope CurrentUser -Force"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Install-Module -Name PSWindowsUpdate -Scope AllUsers -Repository PSGallery"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "powershell.exe",
     "command_line": r'powershell.exe -Command "Update-Help -Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\Backup-UserProfiles.ps1'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -ExecutionPolicy RemoteSigned -File \\fs01\it\scripts\Get-DiskUsage.ps1 -Drive C'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "SYSTEM", "parent_process": "svchost.exe",
     "command_line": r'powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\Scripts\Rotate-IISLogs.ps1'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-Volume | Format-Table DriveLetter, FileSystemLabel, SizeRemaining, Size"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-ComputerInfo | Select-Object OsName, OsVersion, CsSystemType"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'powershell.exe -Command "Test-NetConnection fs01.corp.contoso.com -Port 445"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Resolve-DnsName intranet.corp.contoso.com"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-SmbShare | Format-Table Name, Path, Description"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": "powershell.exe -Command \"Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName, TaskPath\""},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-LocalUser | Format-Table Name, Enabled, LastLogon"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'powershell.exe -Command "Get-LocalGroupMember -Group Administrators"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-Acl C:\Shares\Finance | Format-List Owner, AccessToString"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": 'powershell.exe -Command "Get-Counter \'\\Processor(_Total)\\% Processor Time\' -SampleInterval 2 -MaxSamples 5"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Restart-Service -Name Spooler -Verbose"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": "powershell.exe -Command \"Get-AppxPackage -AllUsers | Where-Object Name -like '*Store*' | Select-Object Name, Version\""},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'powershell.exe -Command "Compress-Archive -Path C:\Logs\*.log -DestinationPath D:\Archive\logs-2026-07.zip -Force"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Copy-Item -Path \\fs01\deploy\ContosoAgent.msi -Destination C:\Temp"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime, FreePhysicalMemory"'},
    {"category": "powershell", "event_id": 1, "process_name": "powershell.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": "powershell.exe -Command \"Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Format-Table DeviceID, FreeSpace, Size\""},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Invoke-WebRequest -Uri https://download.microsoft.com/download/vc_redist.x64.exe -OutFile C:\Temp\vc_redist.x64.exe"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'powershell.exe -Command "Get-ExecutionPolicy -List"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"'},
    {"category": "powershell", "event_id": 4688, "process_name": "powershell.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'powershell.exe -Command "Get-ADUser -Identity jsmith -Properties LockedOut, PasswordLastSet"'},

    # ── cmd: filesystem and log housekeeping ──────────────────────────────────
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c dir /s C:\inetpub\logs\LogFiles'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c del /q C:\Windows\Temp\*.tmp'},
    {"category": "cmd", "event_id": 1, "process_name": "cmd.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'cmd.exe /c rmdir /s /q C:\Temp\build_old'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'cmd.exe /c copy /y C:\Logs\app.log D:\Archive\app-20260720.log'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'cmd.exe /c xcopy C:\Data D:\Backup\Data /E /D /Y'},
    {"category": "cmd", "event_id": 1, "process_name": "cmd.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c type C:\Windows\Logs\DISM\dism.log'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c findstr /i "error" C:\Windows\Logs\CBS\CBS.log'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c echo %COMPUTERNAME% %USERNAME%'},
    {"category": "cmd", "event_id": 1, "process_name": "cmd.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'cmd.exe /c forfiles /p D:\Logs /s /m *.log /d -30 /c "cmd /c del @path"'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'cmd.exe /c mklink /d C:\Shares\Current D:\Releases\2026.07'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'cmd.exe /c fsutil volume diskfree C:'},
    {"category": "cmd", "event_id": 1, "process_name": "cmd.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c chkdsk D: /scan'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'cmd.exe /c wevtutil qe Application /c:20 /f:text /rd:true'},
    {"category": "cmd", "event_id": 4688, "process_name": "cmd.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /c ver'},
    {"category": "cmd", "event_id": 1, "process_name": "cmd.exe",
     "user_name": "CORP\\jsmith", "parent_process": "explorer.exe",
     "command_line": r'cmd.exe /k title Patch-Window-Maintenance'},

    # ── reg: query/add of benign settings, config export ──────────────────────
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v TimeZoneKeyName'},
    {"category": "reg", "event_id": 1, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f'},
    {"category": "reg", "event_id": 1, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'reg.exe export "HKLM\SOFTWARE\Contoso\AppConfig" C:\Backup\appconfig-20260721.reg /y'},
    {"category": "reg", "event_id": 1, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Domain'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "SYSTEM", "parent_process": "svchost.exe",
     "command_line": r'reg.exe add "HKLM\SOFTWARE\Contoso\Inventory" /v LastScan /t REG_SZ /d 2026-07-21 /f'},
    {"category": "reg", "event_id": 4688, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell'},
    {"category": "reg", "event_id": 1, "process_name": "reg.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA'},

    # ── schtasks: query/create/change of backup and update jobs ───────────────
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /query /fo TABLE'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /query /fo LIST /v /tn "\Microsoft\Windows\Defrag\ScheduledDefrag"'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'schtasks.exe /create /tn "Contoso\NightlyDbBackup" /tr "powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\Backup-Databases.ps1" /sc daily /st 02:00 /ru SYSTEM'},
    {"category": "schtasks", "event_id": 1, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /create /tn "Contoso\WeeklyLogRotation" /tr "C:\Scripts\rotate_logs.cmd" /sc weekly /d SUN /st 03:30 /ru SYSTEM'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /create /tn "Contoso\AgentUpdateCheck" /tr "C:\Program Files\Contoso Agent\updater.exe --check" /sc daily /st 06:00'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /change /tn "Contoso\NightlyDbBackup" /st 01:30'},
    {"category": "schtasks", "event_id": 1, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /run /tn "Contoso\WeeklyLogRotation"'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /query /tn "Contoso\NightlyDbBackup" /v /fo LIST'},
    {"category": "schtasks", "event_id": 4688, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /end /tn "Contoso\WeeklyLogRotation"'},
    {"category": "schtasks", "event_id": 1, "process_name": "schtasks.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'schtasks.exe /delete /tn "Contoso\OldInventoryScan" /f'},

    # ── net: drive mapping, share/user/service queries ────────────────────────
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'net.exe use'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'net.exe use Z: \\fs01\public /persistent:yes'},
    {"category": "net", "event_id": 1, "process_name": "net.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'net.exe use Z: /delete'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'net.exe view \\fs01'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe view /domain'},
    {"category": "net", "event_id": 1, "process_name": "net.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'net.exe user jsmith /domain'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'net.exe user'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe accounts'},
    {"category": "net", "event_id": 1, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe share'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe session'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'net.exe statistics workstation'},
    {"category": "net", "event_id": 1, "process_name": "net.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'net.exe start spooler'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'net.exe stop spooler'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe localgroup Administrators'},
    {"category": "net", "event_id": 1, "process_name": "net.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'net.exe time \\dc01'},
    {"category": "net", "event_id": 4688, "process_name": "net.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'net.exe config workstation'},

    # ── wmic: hardware/software/patch inventory queries ───────────────────────
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe os get Caption,Version,BuildNumber /value'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe logicaldisk get DeviceID,Size,FreeSpace'},
    {"category": "wmic", "event_id": 1, "process_name": "wmic.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe product get Name,Version'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe cpu get Name,NumberOfCores,MaxClockSpeed'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe memorychip get Capacity,Speed,Manufacturer'},
    {"category": "wmic", "event_id": 1, "process_name": "wmic.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe qfe list brief'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe bios get SerialNumber'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe computersystem get Model,Manufacturer,TotalPhysicalMemory'},
    {"category": "wmic", "event_id": 1, "process_name": "wmic.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe printer get Name,PortName,PrinterStatus'},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": "wmic.exe service where \"Name='Spooler'\" get State,StartMode"},
    {"category": "wmic", "event_id": 4688, "process_name": "wmic.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'wmic.exe diskdrive get Model,Status,Size'},
    {"category": "wmic", "event_id": 1, "process_name": "wmic.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": "wmic.exe path win32_networkadapter where \"NetEnabled='true'\" get Name,Speed"},

    # ── sc: service status queries ────────────────────────────────────────────
    {"category": "sc", "event_id": 4688, "process_name": "sc.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'sc.exe query Spooler'},
    {"category": "sc", "event_id": 4688, "process_name": "sc.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'sc.exe query state= all'},
    {"category": "sc", "event_id": 1, "process_name": "sc.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'sc.exe qc wuauserv'},
    {"category": "sc", "event_id": 4688, "process_name": "sc.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'sc.exe queryex WinDefend'},
    {"category": "sc", "event_id": 4688, "process_name": "sc.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'sc.exe query BITS'},
    {"category": "sc", "event_id": 1, "process_name": "sc.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'sc.exe qdescription Dhcp'},
    {"category": "sc", "event_id": 4688, "process_name": "sc.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'sc.exe query type= service state= inactive'},

    # ── robocopy: scheduled and ad-hoc backups ────────────────────────────────
    {"category": "robocopy", "event_id": 4688, "process_name": "robocopy.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'robocopy.exe C:\Data D:\Backup\Data /MIR /R:2 /W:5 /LOG:C:\Logs\backup-data.log'},
    {"category": "robocopy", "event_id": 1, "process_name": "robocopy.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'robocopy.exe \\fs01\profiles \\fs02\profiles_backup /E /COPYALL /LOG+:C:\Logs\profile-sync.log'},
    {"category": "robocopy", "event_id": 4688, "process_name": "robocopy.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'robocopy.exe C:\inetpub\wwwroot D:\Archive\wwwroot-20260720 /E /DCOPY:T'},
    {"category": "robocopy", "event_id": 1, "process_name": "robocopy.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'robocopy.exe D:\Logs \\fs01\logarchive\web01 /MOV /MINAGE:30 /NP'},
    {"category": "robocopy", "event_id": 4688, "process_name": "robocopy.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'robocopy.exe C:\Users\jsmith\Documents \\fs01\home\jsmith\Documents /E /XO'},
    {"category": "robocopy", "event_id": 4688, "process_name": "robocopy.exe",
     "user_name": "CORP\\svc_backup", "parent_process": "svchost.exe",
     "command_line": r'robocopy.exe D:\SQLBackups \\fs02\sqlarchive /E /Z /R:1 /W:10'},
    {"category": "robocopy", "event_id": 1, "process_name": "robocopy.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'robocopy.exe C:\ProgramData\Contoso\Config \\fs01\configbackup\web01 /E'},
    {"category": "robocopy", "event_id": 4688, "process_name": "robocopy.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'robocopy.exe D:\Releases\2026.07 \\fs01\deploy\current /MIR /LOG:C:\Logs\deploy-sync.log'},

    # ── network_diag: connectivity and name-resolution troubleshooting ────────
    {"category": "network_diag", "event_id": 4688, "process_name": "ipconfig.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ipconfig.exe /all'},
    {"category": "network_diag", "event_id": 4688, "process_name": "ipconfig.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ipconfig.exe /flushdns'},
    {"category": "network_diag", "event_id": 1, "process_name": "ipconfig.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ipconfig.exe /release'},
    {"category": "network_diag", "event_id": 1, "process_name": "ipconfig.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ipconfig.exe /renew'},
    {"category": "network_diag", "event_id": 4688, "process_name": "netstat.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'netstat.exe -ano'},
    {"category": "network_diag", "event_id": 4688, "process_name": "netstat.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'netstat.exe -e -s'},
    {"category": "network_diag", "event_id": 1, "process_name": "ping.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ping.exe -n 4 fs01.corp.contoso.com'},
    {"category": "network_diag", "event_id": 4688, "process_name": "ping.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'ping.exe -n 2 10.20.0.1'},
    {"category": "network_diag", "event_id": 4688, "process_name": "nslookup.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'nslookup.exe intranet.corp.contoso.com'},
    {"category": "network_diag", "event_id": 1, "process_name": "tracert.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'tracert.exe -d fs01.corp.contoso.com'},
    {"category": "network_diag", "event_id": 4688, "process_name": "arp.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'arp.exe -a'},
    {"category": "network_diag", "event_id": 4688, "process_name": "route.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'route.exe print'},
    {"category": "network_diag", "event_id": 1, "process_name": "nltest.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'nltest.exe /dsgetdc:corp.contoso.com'},
    {"category": "network_diag", "event_id": 4688, "process_name": "whoami.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'whoami.exe /groups'},

    # ── certutil: certificate verification and store inspection ───────────────
    {"category": "certutil", "event_id": 4688, "process_name": "certutil.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'certutil.exe -verify C:\Certs\webserver01.cer'},
    {"category": "certutil", "event_id": 4688, "process_name": "certutil.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'certutil.exe -store My'},
    {"category": "certutil", "event_id": 1, "process_name": "certutil.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'certutil.exe -store Root'},
    {"category": "certutil", "event_id": 4688, "process_name": "certutil.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'certutil.exe -dump C:\Certs\contoso-issuing-ca.crt'},
    {"category": "certutil", "event_id": 1, "process_name": "certutil.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "powershell.exe",
     "command_line": r'certutil.exe -hashfile C:\Temp\vc_redist.x64.exe SHA256'},

    # ── sysadmin_misc: patching, GP, health checks, session management ────────
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "tasklist.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'tasklist.exe /svc'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "tasklist.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'tasklist.exe /fi "IMAGENAME eq chrome.exe"'},
    {"category": "sysadmin_misc", "event_id": 1, "process_name": "taskkill.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'taskkill.exe /im notepad.exe /f'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "systeminfo.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'systeminfo.exe'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "gpupdate.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'gpupdate.exe /force'},
    {"category": "sysadmin_misc", "event_id": 1, "process_name": "gpresult.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'gpresult.exe /r'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "dism.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'dism.exe /online /cleanup-image /restorehealth'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "sfc.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'sfc.exe /scannow'},
    {"category": "sysadmin_misc", "event_id": 1, "process_name": "defrag.exe",
     "user_name": "SYSTEM", "parent_process": "svchost.exe",
     "command_line": r'defrag.exe C: /O'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "wevtutil.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'wevtutil.exe qe System /c:50 /rd:true /f:text'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "powercfg.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'powercfg.exe /list'},
    {"category": "sysadmin_misc", "event_id": 1, "process_name": "w32tm.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'w32tm.exe /query /status'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "quser.exe",
     "user_name": "CORP\\helpdesk2", "parent_process": "cmd.exe",
     "command_line": r'quser.exe'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "hostname.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'hostname.exe'},
    {"category": "sysadmin_misc", "event_id": 1, "process_name": "cleanmgr.exe",
     "user_name": "SYSTEM", "parent_process": "svchost.exe",
     "command_line": r'cleanmgr.exe /sagerun:1'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "shutdown.exe",
     "user_name": "CORP\\admin.mlopez", "parent_process": "cmd.exe",
     "command_line": r'shutdown.exe /r /t 300 /c "Monthly patching reboot"'},
    {"category": "sysadmin_misc", "event_id": 4688, "process_name": "getmac.exe",
     "user_name": "CORP\\jsmith", "parent_process": "cmd.exe",
     "command_line": r'getmac.exe /v'},
]


def _wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI for a binomial proportion (stdlib only)."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def _fp_block(scores: list[float], threshold: float) -> dict:
    """FP count/rate at a decision threshold (all corpus events are benign)."""
    n = len(scores)
    fp = sum(1 for s in scores if s >= threshold)
    lo, hi = _wilson_ci(fp, n)
    return {
        "threshold": threshold,
        "n": n,
        "fp": fp,
        "fp_rate": round(fp / n, 4),
        "wilson_95ci": [round(lo, 4), round(hi, 4)],
    }


def _score_summary(scores: list[float]) -> dict:
    return {
        "min": round(min(scores), 4),
        "median": round(statistics.median(scores), 4),
        "mean": round(statistics.mean(scores), 4),
        "max": round(max(scores), 4),
    }


def _library_versions() -> dict:
    import platform

    import joblib
    import numpy
    import pandas
    import sklearn

    return {
        "python": platform.python_version(),
        "scikit-learn": sklearn.__version__,
        "numpy": numpy.__version__,
        "pandas": pandas.__version__,
        "joblib": joblib.__version__,
    }


def _format_fp_line(label: str, block: dict) -> str:
    lo, hi = block["wilson_95ci"]
    return (
        f"  {label:<28} FP {block['fp']:>3}/{block['n']}"
        f" = {block['fp_rate']*100:6.1f}%  (95% Wilson CI {lo*100:.1f}–{hi*100:.1f}%)"
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    classifier = MLCommandClassifier.from_file(MODEL_PATH, window_size=WINDOW_SIZE)

    events = tuple(
        EventSpec(
            process_name=item["process_name"],
            command_line=item["command_line"],
            user_name=item["user_name"],
            parent_process=item["parent_process"],
            event_id=item["event_id"],
            label="benign",
        )
        for item in CORPUS
    )
    categories = [item["category"] for item in CORPUS]
    n = len(events)

    # ── Model scoring: empty context (flagship-eval harness) + real stream ──
    print(f"Scoring {n} hand-authored benign events with empty context ...")
    scores_empty = [classifier.score_event(ev, (), 0) for ev in events]

    print(f"Scoring with self-consistent context stream (corpus order, k={WINDOW_SIZE}) ...")
    scores_ctx = [classifier.score_event(events[i], events, i) for i in range(n)]

    # ── Rule baselines: any malicious verdict on this corpus is an FP ───────
    wl21_flags = [ev.process_name.lower() not in _BASELINE_PROCESSES for ev in events]
    wl3_flags = [ev.process_name.lower() not in _THREE_PROCESS_WHITELIST for ev in events]
    wl21_fp = sum(wl21_flags)
    wl3_fp = sum(wl3_flags)
    wl21_lo, wl21_hi = _wilson_ci(wl21_fp, n)
    wl3_lo, wl3_hi = _wilson_ci(wl3_fp, n)

    # ── Per-category FP breakdown ───────────────────────────────────────────
    category_order = list(dict.fromkeys(categories))
    per_category = {}
    for cat in category_order:
        idx = [i for i, c in enumerate(categories) if c == cat]
        per_category[cat] = {
            "n": len(idx),
            "model_empty_fp_p40": sum(1 for i in idx if scores_empty[i] >= 0.40),
            "model_ctx_fp_p40": sum(1 for i in idx if scores_ctx[i] >= 0.40),
            "model_empty_fp_p50": sum(1 for i in idx if scores_empty[i] >= 0.50),
            "model_ctx_fp_p50": sum(1 for i in idx if scores_ctx[i] >= 0.50),
            "whitelist21_fp": sum(1 for i in idx if wl21_flags[i]),
            "whitelist3_fp": sum(1 for i in idx if wl3_flags[i]),
        }

    results = {
        "provenance": {
            "source": "hand-authored",
            "authored": "2026-07-21, project authors, adversarial-review remediation (findings 1 and 6)",
            "description": (
                "Benign Windows admin-activity corpus stored as the CORPUS literal in "
                "runs/run_hard_benign_eval.py. Every event is realistic sysadmin activity "
                "using processes OUTSIDE the 21-entry baseline whitelist; every malicious "
                "verdict is a false positive."
            ),
            "limitations": [
                "Hand-authored, not captured telemetry: event frequencies and command-line "
                "phrasing were chosen by the authors, so FP rates here are not deployment "
                "FP-rate estimates.",
                "Measures whether the model can EVER say benign for non-whitelist processes; "
                "a model can pass this corpus and still false-positive heavily on real traffic.",
                "All events are EID 1/4688 process creations. The benign EID 4698 task-created "
                "events that a schtasks /create would also emit are excluded: the classifier "
                "hard-codes 0.99 for _ATTACK_EVENT_IDS, so those would be FPs by construction "
                "(a separate known limitation of the deterministic override).",
                "The context stream is the corpus in authored (category-grouped) order, "
                "approximating an admin working through related tasks on one host — not a "
                "real host timeline interleaved with baseline process noise.",
                "Every corpus process is outside the baseline whitelist by design, so both "
                "rule baselines flag 100% of events; they are included as the contrast the "
                "review asked for, not as deployment-plausible detectors.",
            ],
        },
        "corpus": {
            "n": n,
            "categories": {cat: categories.count(cat) for cat in category_order},
            "unique_processes": sorted({ev.process_name for ev in events}),
            "unique_command_lines": len({ev.command_line for ev in events}),
        },
        "library_versions": _library_versions(),
        "model": {
            "path": str(MODEL_PATH.relative_to(REPO_ROOT)),
            "window_size": WINDOW_SIZE,
            "empty_context": {
                "scores": _score_summary(scores_empty),
                "fp_at": [_fp_block(scores_empty, t) for t in THRESHOLDS],
            },
            "context_stream_k10": {
                "scores": _score_summary(scores_ctx),
                "fp_at": [_fp_block(scores_ctx, t) for t in THRESHOLDS],
            },
        },
        "rule_baselines": {
            "whitelist_21": {
                "rule": "malicious iff process_name not in _BASELINE_PROCESSES (21 entries)",
                "fp": wl21_fp, "n": n, "fp_rate": round(wl21_fp / n, 4),
                "wilson_95ci": [round(wl21_lo, 4), round(wl21_hi, 4)],
            },
            "whitelist_3": {
                "rule": "malicious iff process_name not in {svchost.exe, explorer.exe, runtimebroker.exe}",
                "fp": wl3_fp, "n": n, "fp_rate": round(wl3_fp / n, 4),
                "wilson_95ci": [round(wl3_lo, 4), round(wl3_hi, 4)],
            },
        },
        "per_category": per_category,
        "per_event": [
            {
                "category": categories[i],
                "process_name": events[i].process_name,
                "command_line": events[i].command_line,
                "event_id": events[i].event_id,
                "score_empty_context": round(scores_empty[i], 4),
                "score_context_stream": round(scores_ctx[i], 4),
            }
            for i in range(n)
        ],
    }

    # ── Summary ─────────────────────────────────────────────────────────────
    versions = results["library_versions"]
    summary_lines = [
        "Hard-Benign Evaluation: legitimate admin use of non-whitelist tooling",
        "=" * 70,
        "",
        f"Corpus: {n} hand-authored benign Windows admin events "
        f"({len(category_order)} categories, "
        f"{results['corpus']['unique_command_lines']} unique command lines).",
        "Provenance: hand-authored by the project authors (2026-07-21) for the",
        "adversarial-review remediation — NOT captured telemetry. Every process is",
        "outside the 21-entry baseline whitelist, so every malicious verdict below",
        "is a false positive. This eval measures whether the deployed model can",
        "EVER say benign for non-whitelist processes; it does not estimate a",
        "deployment FP rate.",
        "",
        f"Model: {results['model']['path']} (MLCommandClassifier, k={WINDOW_SIZE})",
        "",
        "Empty context (matches the flagship-eval harness):",
        _format_fp_line("p* >= 0.40:", _fp_block(scores_empty, 0.40)),
        _format_fp_line("p* >= 0.50:", _fp_block(scores_empty, 0.50)),
        "  scores: min={min}  median={median}  mean={mean}  max={max}".format(
            **results["model"]["empty_context"]["scores"]
        ),
        "",
        f"Self-consistent context stream (corpus order, k={WINDOW_SIZE}):",
        _format_fp_line("p* >= 0.40:", _fp_block(scores_ctx, 0.40)),
        _format_fp_line("p* >= 0.50:", _fp_block(scores_ctx, 0.50)),
        "  scores: min={min}  median={median}  mean={mean}  max={max}".format(
            **results["model"]["context_stream_k10"]["scores"]
        ),
        "",
        "Rule baselines (contrast — flag 100% by construction, since every corpus",
        "process is non-whitelist):",
        f"  21-entry whitelist rule:     FP {wl21_fp:>3}/{n} = {wl21_fp/n*100:6.1f}%"
        f"  (95% Wilson CI {wl21_lo*100:.1f}–{wl21_hi*100:.1f}%)",
        f"  3-process whitelist rule:    FP {wl3_fp:>3}/{n} = {wl3_fp/n*100:6.1f}%"
        f"  (95% Wilson CI {wl3_lo*100:.1f}–{wl3_hi*100:.1f}%)",
        "",
        "Per-category FP breakdown (model, p* >= 0.40):",
        f"  {'Category':<16} {'n':>4} {'empty-ctx':>10} {'ctx-stream':>11} {'WL-21':>6} {'WL-3':>6}",
        f"  {'-'*58}",
    ]
    for cat in category_order:
        row = per_category[cat]
        summary_lines.append(
            f"  {cat:<16} {row['n']:>4} {row['model_empty_fp_p40']:>10}"
            f" {row['model_ctx_fp_p40']:>11} {row['whitelist21_fp']:>6} {row['whitelist3_fp']:>6}"
        )
    summary_lines += [
        "",
        "Limitations:",
    ]
    summary_lines += [f"  - {item}" for item in results["provenance"]["limitations"]]
    summary_lines += [
        "",
        "Library versions: "
        + ", ".join(f"{k}={v}" for k, v in versions.items()),
    ]

    summary = "\n".join(summary_lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
