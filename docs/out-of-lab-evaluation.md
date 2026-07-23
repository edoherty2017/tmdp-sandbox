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

## 2. DARPA OpTC — PARTIALLY RUN (real enterprise telemetry, benign window)

Update 2026-07-23: we **did** run OpTC on a real slice. Google Drive was reachable
via `gdown`, so we pulled the `ecar/evaluation/23Sep19-red/AIA-201-225` main chunk
(110 MB, downloaded in seconds) — the host range containing **SysClient0201**, the
Day-1 red-team target. Script: `runs/run_optc_outoflab_eval.py`; artifacts:
`runs/optc_outoflab_eval/`. The eCAR→`EventSpec` adapter (PROCESS/CREATE→EID1,
PROCESS/OPEN→EID10, MODULE/LOAD→EID7, REGISTRY→EID13) is in the script.

**What this slice covers:** SysClient0201 on 2019-09-23, ~09:06–09:31 — a **pre-attack
benign window** (the red team began at 11:23 per the ground-truth PDF). So this is a
real-world **false-positive / whitelist-equivalence** test on genuine enterprise
telemetry — the strongest of the three corpora for that purpose (OTRF and EVTX are both
attack-focused simulations; this is real background activity).

**Result (3,879 scored process/module/registry events):**

> - **Label-free headline — model vs 21-process whitelist agreement: 3,877 / 3,879 =
>   99.95%.** Whitelist-equivalence holds on a THIRD, real-world corpus.
> - **Model flags 1,676 / 3,879 = 43.2% of events as malicious** (95% Wilson CI
>   41.7–44.8%). This window is benign, so **every one of those is a real-world false
>   positive on genuine enterprise activity** — the deployment-FP concern, now measured
>   on real data rather than the 152 hand-authored commands of §6.7.2. A whitelist-shaped
>   detector drowns in false positives against real enterprise process diversity.

**Not yet done (honest):** attack *detection* on OpTC. The red-team window (11:23–15:30)
lives in the 2.2 GB `-last` chunk, which throttled to ~1.3 MB/s and reset mid-download in
this sandbox. The harness is wired to score it; a stable pull (Colab in-place, or a
resumed `gdown`) plus frozen labels from the red-team log (host/time/indicator-scoped) is
all that remains to get an OpTC attack-detection P/R.

### Reproducing / extending (for whoever finishes the attack-detection run)

DARPA Operationally Transparent Cyber (OpTC) is the stronger target — real red-team
activity with authoritative ground truth. The benign-window run above is done; the
attack-detection run is what remains. The "1 TB download" is not the blocker. Hosting
details, verified 2026-07-23:

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
