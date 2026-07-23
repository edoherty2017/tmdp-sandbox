# Dataset Examples

Real events from the datasets, so you can see exactly what the classifier reads. The raw
data is **not committed** (too large / licensing — see download links below), so these
concrete samples live here.

Each event, after parsing, becomes a record with these fields (this is all the model sees):

| field | meaning |
|---|---|
| `event_id` | Windows / Sysmon Event ID (1 = process created, 10 = process opened another, 12/13 = registry, 7 = DLL loaded, 4104 = PowerShell script, 1102 = audit log cleared) |
| `process_name` | the program that acted |
| `parent_process` | what launched it (or, for EID 10, the process being opened) |
| `command_line` | the command text / event detail |
| `label` | ground truth: `malicious` / `benign` (assigned by the frozen `auto_label_event` rule) |

---

## 1. OTRF Security Datasets (training + main eval)

Source: [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) —
Windows Sysmon/Security logs from simulated attacks. Training pool = **11,791 benign /
144 malicious** events.

### 🔴 Malicious examples

**Audit log cleared** (attackers hide their tracks) — EID 1102
```
process: microsoft-windows-eventlog
command: "The audit log was cleared. Subject: Account Name: wardog, Domain: WORKSTATION5 ..."
label:   malicious   (EID 1102 = log wipe → always flagged)
```

**LOLBin service abuse** (hijack the Fax service to run PowerShell) — EID 4688 / 1
```
process: sc.exe        parent: cmd.exe
command: sc config Fax binPath= "...\powershell.exe -noexit -c \"write-host 'T1543.003 Test'\""
label:   malicious   (sc.exe reconfiguring a service to launch PowerShell)
```

**Obfuscated PowerShell** (encoded payload pulled from the registry) — EID 4104
```
process: microsoft-windows-powershell
command: $x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -W Hidden -enc $x
label:   malicious   (hidden window + base64 -enc = obfuscation)
```

**Registry persistence** (UAC-bypass key) — EID 12
```
process: powershell.exe
command: reg CreateKey HKU\...\ms-settings\Shell=
label:   malicious   (writes a known UAC-bypass registry path)
```

### 🟢 Benign examples

**Normal Explorer registry write** — EID 13
```
process: explorer.exe
command: reg SetValue HKU\...\CurrentVersion\Explorer\FeatureUsage\AppSwitched\...
label:   benign   (explorer.exe is a known-good baseline process)
```

**Signed Microsoft DLL load** — EID 7
```
process: conhost.exe
command: load C:\Windows\System32\edputil.dll signed=true sig=Microsoft Windows
label:   benign   (signed Microsoft DLL, baseline process)
```

> 👉 **This is the whole problem in two lines:** the malicious `powershell.exe`/`sc.exe`
> events aren't on the 21-process baseline list, and the benign `explorer.exe`/`conhost.exe`
> events are. The classifier learned to split on exactly that — so it behaves like a
> whitelist (see README "Results at a glance").

---

## 2. EVTX-ATTACK-SAMPLES (out-of-lab test #1)

Source: [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
— 278 attack captures, a different author/environment than OTRF. Example malicious events
(see `runs/evtx_outoflab_eval/ground_truth_labels.json` for the full frozen label set):

```
AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx  (events 19, 21)
AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx                              (event 3)
```
Result: the OTRF-trained model agreed with the 21-process whitelist on **100%** of 1,120
events here too.

---

## 3. DARPA OpTC (out-of-lab test #2 — real enterprise telemetry)

Source: [github.com/FiveDirections/OpTC-data](https://github.com/FiveDirections/OpTC-data)
(data on Google Drive; eCAR format). A **real** event from SysClient0201, 2019-09-23:

```
object/action: PROCESS/CREATE   (→ EID 1)
process: cmd.exe        parent: svchost.exe        user: NT AUTHORITY\SYSTEM
command: C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
timestamp: 2019-09-23T09:07:00-04:00   (benign, pre-attack window)
```
Result on this real enterprise data: **99.95%** whitelist agreement, and the model flagged
**43%** of genuinely benign events as malicious (false positives).

---

## How to get the raw data yourself

```
OTRF:  git clone https://github.com/OTRF/Security-Datasets   → ZIPs into data/raw/malicious/ and data/raw/eval_holdout/
EVTX:  git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES   → data/raw/evtx_attack_samples/
OpTC:  gdown the red-team slice from the Drive folder (see docs/out-of-lab-evaluation.md)
```
Exact ZIP lists are in `runs/train_classifier.py` and `runs/run_large_independent_eval.py`.
