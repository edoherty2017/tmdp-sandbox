# Out-of-Lab Evaluation (2026-07-23)

The review's central limitation was that every number came from the OTRF/Mordor
`theshire` lab — the same hosts, operator, and recording pipeline for both training
and "held-out" data, so nothing was ever tested out of distribution. This note
covers the two out-of-lab corpora we targeted.

## 1. EVTX-ATTACK-SAMPLES (sbousseaden) — DONE, real result

An independently collected corpus of Windows event-log captures (Sysmon + Security
channels) organized by MITRE ATT&CK, authored by a different researcher on different
machines than OTRF. Script: `runs/run_evtx_outoflab_eval.py`; artifacts:
`runs/evtx_outoflab_eval/`. Same corrected labels-first protocol as the OTRF eval
(frozen `auto_label_event` labels committed before scoring; real k=10 context
windows; OTRF-trained logistic model).

**Corpus:** 278 `.evtx` files, 37,364 events → 1,120 labeled (681 malicious, 439
benign), 36,244 excluded as ambiguous.

**Result (label-free headline — the number that matters):**

> The OTRF-trained model's predictions coincide with a 21-process whitelist rule on
> **1,120 / 1,120 = 100.0%** of events — and it is 100% at every one of the 11 ATT&CK
> tactics. The exact whitelist-equivalence found on OTRF **holds out of distribution**:
> the model did not learn anything transferable beyond process-name membership.

**On the P/R/F1 (P=R=F1=1.000):** this is a **circular artifact, not a success.** The
frozen labeler (`auto_label_event`) keys on the same process/EID vocabulary as both the
model's features and the whitelist, so labels ≈ whitelist ≈ model by construction — all
three collapse to "is the process on the baseline list." The perfect score therefore
says nothing about detection skill; it is reported only for transparency and is flagged
as circular in `summary.txt`. The **whitelist-agreement rate is label-free** (it never
touches the labels) and is the honest, defensible finding.

**Takeaway for the report:** this strengthens, rather than rescues, the honest
conclusion. On a second, independently sourced corpus the classifier remains
behaviorally indistinguishable from a 21-line whitelist. To show any real detection
value we would need labels derived from attack *content* (command line, registry,
network) rather than process membership — see the limitation below.

**Known limitation of this eval:** because the labeler is process/EID-based, it cannot
expose the model's blind spot (attacks that run under whitelisted processes, e.g. the
lsass/svchost cases that sank the OTRF eval). A content-signature labeler, independent
of process name, is the next refinement and would make P/R/F1 meaningful.

## 2. DARPA OpTC — feasible WITHOUT the full 1 TB (not run in this sandbox)

DARPA Operationally Transparent Cyber (OpTC) is the stronger target — real red-team
activity with authoritative ground truth. We did not run it *here* (this sandbox has no
Google-Drive access), and we will not fabricate numbers for it. But the "1 TB download"
is not actually the blocker. Hosting details, verified 2026-07-23:

- The public repo `github.com/FiveDirections/OpTC-data` is **documentation only**
  (`OpTCRedTeamGroundTruth.pdf`, `README.md`, `ecar.md`, `errata.md`) — no event data.
- The data lives on a **public Google Drive folder**
  (`1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa`), split into `ecar/`, `ecar-bro/`, `bro/`, each
  with `short/`, `evaluation/`, `benign/` subfolders, as **per-host, per-day** files.

### You do not need the whole 1 TB — three ways to use it cheaply

1. **Download only the red-team slice (recommended).** The red-team activity is scoped to
   a handful of hosts on specific days (Sept 2019), all enumerated in
   `OpTCRedTeamGroundTruth.pdf`. Pull just those host files from `ecar/evaluation/` plus a
   few benign host-days as negatives — **single-digit to low-tens of GB, not 1 TB.**
   `gdown` fetches individual Drive files by ID without auth (`pip install gdown`), so you
   grab only the files you need, not the folder.
2. **Process it in place in Google Colab.** Colab mounts the Drive folder directly, so the
   data never lands on a local machine — you run the adapter + scoring in the cloud on
   whatever subset you point at.
3. **Stream-filter a single compressed file at a time.** eCAR files are line-delimited
   JSON; download one host file, `zcat | filter` the PROCESS/CREATE records you need, and
   discard the rest — never holding the full decompressed corpus.

What is *not* possible: server-side grep/range-filtering of Google Drive (Drive returns
whole files). So "zero download" isn't achievable, but "tens of GB instead of 1 TB" is.

### The adapter is straightforward — eCAR maps cleanly to our `EventSpec`

From `ecar.md`, a `PROCESS/CREATE` eCAR record carries everything we need in
`properties`:

| eCAR field | → `EventSpec` |
|---|---|
| `basename(properties.image_path)` | `process_name` |
| `properties.command_line` | `command_line` |
| `basename(properties.parent_image_path)` | `parent_process` |
| `properties.user` | `user_name` |
| `object`+`action` (e.g. PROCESS/CREATE) | mapped to a synthetic `event_id` |

So the real work is: (1) grab the red-team host slice via `gdown`, (2) ~30-line
eCAR→`EventSpec` adapter (schema above), (3) frozen labels from the ground-truth PDF
(time/host-scoped) committed before scoring, (4) run the same harness as the EVTX eval
and report P/R/F1 + the label-free whitelist-agreement rate. It is a scoped engineering
task, not a research unknown — I can write steps 2–4 now against a small downloaded
sample whenever someone pulls one.
