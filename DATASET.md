# DATASET.md

# AI-EDR Dataset Specification

**Project:** Local-First AI-Assisted Endpoint Detection and Response
**Document:** `DATASET.md`
**Status:** Research Baseline
**Version:** 0.1
**Purpose:** Define the datasets, dataset hierarchy, ingestion strategy, labeling, splits, provenance, and future Windows endpoint telemetry required to train and evaluate the EDR.

---

## 1. Purpose

This document defines the data strategy for the AI-EDR project.

The project uses a **multi-source dataset architecture** rather than treating one public intrusion-detection dataset as the complete training dataset.

The immediate public dataset is **ADFA-WD**, specifically its Full Process Traces. ADFA-WD is useful for researching system-call sequence detection and establishing an initial benchmark, but it does not provide the complete event context required by a modern endpoint detection system.

The eventual primary dataset will therefore be generated from a controlled **Windows 11 EDR research laboratory** using the project's own canonical event schema.

The governing principle is:

> **Preserve source evidence first, normalize second, engineer features third, and train models only from representations whose meaning is known.**

---

# 2. Dataset Strategy

The project maintains three conceptual dataset tiers.

```text
                    DATASET STRATEGY
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
         ADFA-WD        ADFA-WD:SAA   Windows 11 Lab
             │             │             │
       Benchmark       Evaluation      Primary Data
       Research        / General-      Source
       / Sequence      ization
       Models
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                    SOURCE ADAPTERS
                           │
                           ▼
                    CANONICAL SCHEMA
                           │
                           ▼
                    FEATURE DATASETS
                           │
                           ▼
                         MODELS
```

### Tier 1 — Public Research Data

Used to establish reproducible experiments and compare system-call sequence approaches with published work.

Primary source:

* ADFA-WD Full Process Traces

### Tier 2 — Public Generalization Data

Used after the baseline has been established to test whether a detector can generalize beyond the data used to develop it.

Primary source:

* ADFA-WD:SAA

Additional Windows datasets may be evaluated later, including datasets containing richer system-call information.

### Tier 3 — Project-Native Endpoint Data

This is the long-term primary dataset.

It will be collected from the project's controlled Windows 11 laboratory using:

* Sysmon
* Windows Event Logs
* PowerShell logging
* EDR sensor telemetry
* controlled benign activity
* controlled attack/suspicious activity
* experiment metadata
* analyst-confirmed ground truth

The project-native dataset is the dataset that will ultimately determine whether the EDR works against the event model it is actually designed to understand.

---

# 3. Why ADFA-WD Is Not the Final Dataset

ADFA-WD is explicitly designed for evaluation of **system-call-based host intrusion detection systems**. UNSW provides the Windows dataset as a set of Full Process Traces and separately provides the Stealth Attacks Addendum.

This makes ADFA-WD valuable for the first stage of the project, particularly for sequence modelling.

However, the final EDR requires substantially richer endpoint context.

A modern EDR event may need to answer questions such as:

* Which process generated the event?
* What was its parent process?
* What user executed it?
* What command line was used?
* Which executable image was involved?
* Which file was accessed or modified?
* Which registry key was accessed?
* Which network destination was contacted?
* Which module or DLL was loaded?
* When did the activity occur?
* What other events occurred immediately before and after it?
* Which source generated the observation?
* What is known ground truth for the activity?

ADFA-WD does not provide this complete canonical event representation.

Therefore:

> **ADFA-WD is a source dataset, not the canonical representation of the EDR.**

The project must never add fabricated fields merely to make ADFA-WD look like modern endpoint telemetry.

Missing information remains missing.

---

# 4. ADFA-WD

## 4.1 Role

ADFA-WD is the initial public benchmark dataset.

Its primary role is:

1. Establish a reproducible ingestion pipeline.
2. Test sequence tokenization.
3. Establish simple machine-learning baselines.
4. Explore system-call sequence classification.
5. Investigate anomaly and malicious-sequence detection.
6. Measure baseline model performance.
7. Provide a comparison point before introducing project-native telemetry.

UNSW states that ADFA-WD and the other ADFA datasets are intended for system-call-based HIDS evaluation.

---

## 4.2 Local Archive

The locally obtained archive contains the ADFA-WD Full Process Traces and associated ADFA-WD:SAA material.

The Full Process Traces are divided into:

```text
Full Process Traces/
├── Full_Trace_Training_Data/
├── Full_Trace_Validation_Data/
└── Full_Trace_Attack_Data/
```

The locally inspected archive contained approximately:

```text
Training traces:       355
Validation traces:   1,827
Attack traces:       5,542
Total traces:        7,724
```

These figures describe the local archive inspected during dataset analysis and must be treated as **archive verification metadata**, not as assumptions about every future copy of the dataset.

The project should record a checksum for the exact archive used in experiments.

---

# 5. ADFA-WD Source Representation

The primary Full Process Trace representation is an ordered sequence of observations.

Representative values have the form:

```text
ntdll.dll+0x16d33
ntdll.dll+0x16f03
ntdll.dll+0x1ce16
ntdll.dll+0x1ccd2
kernel32.dll+0x1bb9
```

The fundamental unit is therefore:

> **TRACE**

not:

> **individual EDR event**

and not:

> **Windows process event**

A source trace should be represented as:

```json
{
  "trace_id": "uuid",
  "source": {
    "dataset": "ADFA-WD",
    "format": "GHC",
    "partition": "training",
    "source_file": "example.GHC"
  },
  "observations": [
    {
      "position": 0,
      "value": "ntdll.dll+0x16d33"
    },
    {
      "position": 1,
      "value": "ntdll.dll+0x16f03"
    }
  ]
}
```

The following properties must be preserved:

* original file name
* original partition
* trace identity
* observation order
* raw observation value
* parser status
* adapter version
* dataset version

---

# 6. Raw Data Preservation

Raw source data is immutable.

The ingestion process must never overwrite or modify the original dataset.

Recommended storage:

```text
datasets/
└── adfa-wd/
    ├── raw/
    ├── manifests/
    ├── normalized/
    ├── features/
    ├── splits/
    └── reports/
```

The raw directory contains the original extracted data exactly as received.

All transformations occur downstream.

This provides:

* reproducibility
* auditability
* parser debugging
* future reprocessing
* experiment reproducibility
* protection against accidental data corruption

---

# 7. ADFA-WD Parsing

The ADFA-WD adapter must:

1. Read each `.GHC` file.
2. Preserve the raw observation.
3. Assign a trace identifier.
4. Record the source file.
5. Record the original dataset partition.
6. Preserve observation order.
7. Parse module and offset when possible.
8. Report malformed observations.
9. Attach provenance metadata.
10. Produce the canonical representation.

A token such as:

```text
ntdll.dll+0x16d33
```

may be parsed into:

```json
{
  "raw_value": "ntdll.dll+0x16d33",
  "module": "ntdll.dll",
  "offset": "0x16d33"
}
```

The raw value must always remain available.

---

# 8. Canonical Representation

The EDR's canonical representation is deliberately richer than ADFA-WD.

The canonical schema is defined in:

```text
docs/EVENT-SCHEMA.md
```

The conceptual structure is:

```text
event
├── event_id
├── trace_id
├── timestamp
├── host
├── process
├── user
├── activity
├── file
├── registry
├── network
├── module
├── provenance
└── ground_truth
```

Not every source will populate every field.

For example, an ADFA-WD observation may contain:

```json
{
  "activity": {
    "type": "system_call_sequence_observation",
    "raw_value": "ntdll.dll+0x16d33",
    "module": "ntdll.dll",
    "offset": "0x16d33"
  }
}
```

It should **not** invent:

```text
timestamp
process_id
parent_process_id
username
command_line
ip_address
registry_key
file_path
```

when those values are not present in the source.

---

# 9. Future Windows 11 Dataset

The project's primary EDR dataset will be generated in a controlled Windows 11 laboratory.

The purpose of this dataset is to collect events using the same information the eventual endpoint agent will have available during inference.

The initial telemetry sources should include:

```text
Windows 11
   │
   ├── Sysmon
   ├── Windows Event Logs
   ├── PowerShell logging
   └── EDR sensor
            │
            ▼
      Event Collector
            │
            ▼
      Event Normalizer
            │
            ▼
      Canonical Schema
```

The project-native dataset should capture, where available:

### Process telemetry

* process creation
* process termination
* process ID
* parent process ID
* executable path
* executable hash
* command line
* user
* integrity level
* signing information
* creation time

### Module telemetry

* DLL/module load
* module path
* module hash
* publisher/signature information
* process association

### File telemetry

* file creation
* file modification
* file deletion
* rename
* execution
* hashes
* path
* process responsible

### Registry telemetry

* key creation
* value modification
* key/value deletion
* process responsible

### Network telemetry

* connection creation
* source process
* local endpoint
* destination endpoint
* protocol
* timestamp

### Authentication telemetry

* logon
* logoff
* failed authentication
* account
* logon type
* source information where available

### PowerShell telemetry

* script execution
* script block information
* command invocation
* process association
* user
* timestamp

---

# 10. Data Generation

The Windows 11 dataset must be generated through controlled experiments.

Every experiment receives an experiment identifier.

Example:

```text
EXP-000001
```

An experiment record should describe:

```json
{
  "experiment_id": "EXP-000001",
  "host": "WIN11-EDR-01",
  "scenario": "normal_software_install",
  "start_time": "...",
  "end_time": "...",
  "operator": "researcher",
  "environment_version": "lab-v0.1",
  "ground_truth": "benign"
}
```

The dataset must contain both benign and malicious/suspicious activity.

---

# 11. Benign Data

Benign data must not be limited to idle desktop activity.

The EDR needs examples of legitimate activity that may resemble suspicious behavior.

Initial benign scenarios should include:

```text
Normal login/logout
Web browsing
Office/document activity
Software installation
Software removal
Windows Update
Developer tooling
PowerShell administration
Command Prompt use
Scheduled tasks
Service installation
Archive extraction
File copying
File deletion
Network browsing
System administration
Antivirus activity
Normal background processes
```

The objective is to expose the model to realistic variation.

A detector trained only on obviously harmless activity will tend to learn a simplified definition of "normal."

---

# 12. Suspicious and Malicious Data

Malicious and suspicious activity must be generated in isolated, controlled environments.

The initial experiments should focus on observable behaviors rather than attempting to create an enormous malware collection.

Examples include:

```text
Suspicious PowerShell execution
Encoded command execution
Abnormal parent/child process relationships
Persistence mechanisms
Suspicious scheduled task creation
Suspicious service creation
Credential-access simulations
Unusual registry modifications
Suspicious executable creation
Suspicious DLL loading
Unexpected network connections
Command interpreters spawned by unusual parents
Known attack-technique simulations
```

Every experiment must document what was executed and what the expected observable behavior was.

---

# 13. Ground Truth

Ground truth is separate from the event features.

The model must not receive the label as an input feature.

Conceptually:

```text
RAW TELEMETRY
      │
      ▼
CANONICAL EVENT
      │
      ▼
FEATURES ───────────────┐
                        │
                        ▼
                      MODEL
                        │
                        ▼
                  PREDICTION
                        
GROUND TRUTH ──────────► EVALUATION
```

Ground truth should contain information such as:

```json
{
  "label": "malicious",
  "confidence": "confirmed",
  "source": "controlled_experiment",
  "experiment_id": "EXP-000127"
}
```

Ground truth must be derived from the controlled experiment and analyst verification rather than from the model itself.

---

# 14. Initial Label Taxonomy

The first model should use a simple label space.

```text
BENIGN
SUSPICIOUS
MALICIOUS
```

A binary formulation may also be maintained for baseline experiments:

```text
BENIGN
MALICIOUS
```

The project should not create an unnecessarily detailed taxonomy before enough data exists to support it.

Later labels may include:

```text
technique
tactic
severity
confidence
behavior family
investigation outcome
```

MITRE ATT&CK mappings should be introduced only when the underlying evidence supports the mapping.

---

# 15. Dataset Splitting

Data leakage is a major risk in security-machine-learning experiments.

Splitting must occur at the **trace, process, experiment, or host level**, depending on the dataset.

Never split individual observations from the same trace randomly across training and validation sets.

Incorrect:

```text
TRACE A
├── token 1 → training
├── token 2 → validation
├── token 3 → training
└── token 4 → test
```

Correct:

```text
TRACE A ───────────────► training

TRACE B ───────────────► validation

TRACE C ───────────────► test
```

For the Windows laboratory dataset, entire experiments should normally remain together.

Where appropriate, entire hosts or experiment families should also be held out for generalization testing.

---

# 16. Recommended Dataset Splits

The project should maintain three principal partitions:

```text
TRAIN
VALIDATION
TEST
```

A fourth optional partition may be maintained:

```text
GENERALIZATION
```

The generalization partition is intended for scenarios substantially different from the data used to develop the model.

For example:

```text
TRAIN
   └── ordinary laboratory scenarios

VALIDATION
   └── unseen traces from known scenario families

TEST
   └── held-out experiments

GENERALIZATION
   └── new attack families / unseen environments
```

ADFA-WD:SAA should be treated as an external/generalization-oriented evaluation source rather than simply mixing it into the training pool.

UNSW describes ADFA-WD:SAA as a stealth-attack addendum intended for evaluation in conjunction with ADFA-WD.

---

# 17. Feature Leakage Prevention

The following must not be used as model features unless the experiment explicitly investigates them:

* source file name
* attack directory name
* dataset partition
* ground-truth label
* experiment identifier
* researcher annotations
* post-detection information
* analyst verdict
* any field derived from the label

For example, an ADFA attack directory such as:

```text
V10-Backdoored-Executable-S1
```

must not become a feature.

The model should learn from observable behavior, not the name assigned to the experiment.

---

# 18. Sequence Data

The project will initially treat ADFA-WD as sequence data.

Potential representations include:

### Token identity

Each unique observation becomes a vocabulary token.

```text
ntdll.dll+0x16d33 → 1
ntdll.dll+0x16f03 → 2
kernel32.dll+0x1bb9 → 3
```

### Frequency features

Count occurrences of observations.

### N-grams

Represent short sequences such as:

```text
A → B → C
B → C → D
C → D → E
```

### Sequence embeddings

Later experiments may learn dense representations of sequences.

### Sequence models

Only after establishing strong baselines should the project evaluate:

* recurrent models
* temporal convolutional models
* transformer-based sequence models
* small neural architectures

No neural architecture should be considered mandatory in advance.

---

# 19. ADFA-WD Baseline Experiments

The first experiments should be intentionally simple.

Recommended sequence:

```text
1. Statistical baseline
2. Frequency / n-gram representation
3. Logistic Regression
4. Tree-based model
5. Small neural sequence model
```

The purpose is to establish whether increasing model complexity actually improves detection.

The project should not begin with a neural network simply because the end goal contains a neural component.

---

# 20. Project-Native Feature Development

Once Windows 11 telemetry is available, features should be developed around endpoint behavior.

Examples:

```text
process ancestry
process rarity
command-line characteristics
executable reputation features
parent/child relationships
DLL-load patterns
file-write patterns
registry persistence patterns
network destination features
authentication context
temporal relationships
event frequency
event sequence structure
cross-event correlations
```

Features should be derived from the canonical schema rather than directly from vendor-specific raw log syntax.

This keeps the model architecture independent from individual telemetry providers.

---

# 21. Dataset Versioning

Every dataset release must have a version.

Recommended format:

```text
dataset-v0.1
dataset-v0.2
dataset-v1.0
```

A dataset version should identify:

* source datasets
* source checksums
* parser version
* schema version
* feature version
* experiment collection version
* labeling version
* split definition
* exclusions
* preprocessing steps

Example:

```text
Dataset:
    win11-edr-v0.1

Schema:
    event-schema-v0.2

Adapter:
    windows-sysmon-adapter-v0.1

Feature set:
    feature-set-v0.1
```

A model must always record the dataset version from which it was trained.

---

# 22. Dataset Manifest

Every dataset release should contain a manifest.

Example:

```json
{
  "dataset_id": "win11-edr-v0.1",
  "schema_version": "0.2",
  "created_at": "2026-09-23T00:00:00Z",
  "sources": [
    {
      "name": "windows_sysmon",
      "version": "1.x"
    },
    {
      "name": "windows_event_log"
    },
    {
      "name": "powershell_logging"
    },
    {
      "name": "edr_sensor",
      "version": "0.1"
    }
  ],
  "partitions": {
    "train": 0,
    "validation": 0,
    "test": 0
  }
}
```

Counts must be generated automatically rather than manually entered.

---

# 23. Provenance

Every normalized event should be traceable back to its original source.

Minimum provenance fields:

```text
dataset_id
source_type
source_file
source_record
adapter_name
adapter_version
schema_version
ingestion_time
```

For project-native telemetry, provenance should also identify:

```text
host
collector
sensor version
experiment_id
```

The objective is reproducibility:

```text
MODEL
  ↓
FEATURE
  ↓
CANONICAL EVENT
  ↓
RAW EVENT
  ↓
SOURCE
```

---

# 24. Data Quality Checks

Every ingestion pipeline must validate:

### Structural integrity

* required fields
* valid JSON/CSV/XML/GHC parsing
* valid data types
* valid timestamps
* valid identifiers

### Sequence integrity

* observation order
* missing records
* duplicate observations
* corrupted traces

### Label integrity

* label exists
* label is permitted
* no conflicting labels
* ground truth is independent of prediction

### Provenance integrity

* source is known
* source file is known
* adapter version is recorded

### Distribution checks

* class balance
* sequence lengths
* vocabulary size
* event frequency
* missing-field rates

---

# 25. Dataset Statistics

Before every major model experiment, the following statistics should be generated.

For sequence datasets:

```text
number of traces
total observations
mean trace length
median trace length
minimum trace length
maximum trace length
unique token count
top tokens
token frequency distribution
class counts
class proportions
```

For Windows endpoint datasets:

```text
number of events
events per host
events per process
events per experiment
event-type distribution
missing-field percentages
process depth
unique executable count
network-event count
registry-event count
file-event count
authentication-event count
class distribution
scenario distribution
```

Distribution reports should be stored with the experiment.

---

# 26. ADFA-WD:SAA

ADFA-WD:SAA is maintained separately from the ordinary ADFA-WD development data.

It contains stealth attack traces and is intended by UNSW to be evaluated in conjunction with ADFA-WD.

The project should therefore avoid treating SAA as merely additional training rows.

Primary uses:

```text
generalization testing
stealth-behavior evaluation
robustness testing
sequence-model evaluation
```

A model that performs well on ADFA-WD and poorly on SAA should be treated as having limited demonstrated generalization.

---

# 27. Other Public Windows Datasets

Other Windows security datasets may be evaluated after the initial ADFA-WD baseline.

One candidate is **AWSCTD**, which was designed around Windows system-call activity and included substantially richer system-call information in its stated design, including arguments, return values, file changes, and network activity.

AWSCTD should not automatically replace ADFA-WD.

Instead, additional datasets should enter the architecture through source-specific adapters:

```text
ADFA-WD ────────┐
AWSCTD ─────────┤
ADFA-WD:SAA ────┤
Windows 11 ─────┤
                ▼
        CANONICAL SCHEMA
```

This allows different datasets to be compared without pretending that they contain identical information.

---

# 28. Dataset Licensing

Dataset licensing is part of dataset provenance.

The official UNSW ADFA page states that ADFA datasets are free for academic research purposes, while **commercial use is strictly prohibited**.

Therefore:

> **ADFA-WD must not be treated as commercially licensed training material.**

Before any commercial deployment, product distribution, or commercial model training involving ADFA-WD, the project's legal/use rights must be reviewed separately.

The dataset's license and attribution requirements must be preserved with the project metadata.

---

# 29. Privacy and Safety

The Windows laboratory should be designed so that collected telemetry does not accidentally contain unrelated personal data.

The laboratory should use:

* synthetic accounts
* dedicated test machines
* isolated test networks
* controlled credentials
* synthetic documents
* non-production services

The dataset should not contain:

* personal passwords
* production credentials
* private user documents
* unrelated personal communications
* production authentication data

Sensitive values should be redacted or replaced during normalization where necessary, while preserving useful structural information.

---

# 30. Data Storage Architecture

Recommended structure:

```text
datasets/
├── raw/
│   ├── adfa-wd/
│   ├── adfa-wd-saa/
│   └── windows-lab/
│
├── manifests/
│
├── normalized/
│   ├── adfa-wd/
│   ├── adfa-wd-saa/
│   └── windows-lab/
│
├── features/
│
├── splits/
│
├── labels/
│
├── statistics/
│
├── experiments/
│
└── reports/
```

Large immutable data should be stored separately from generated features wherever practical.

---

# 31. Data Flow

The complete dataset pipeline is:

```text
                    RAW SOURCES
                         │
          ┌──────────────┼───────────────┐
          │              │               │
          ▼              ▼               ▼
       ADFA-WD        ADFA-WD:SAA    Windows 11 Lab
          │              │               │
          ▼              ▼               ▼
     ADFA Adapter   SAA Adapter     EDR Adapter
          │              │               │
          └──────────────┼───────────────┘
                         ▼
                 CANONICAL EVENTS
                         │
                         ▼
                  EVENT WINDOWS
                         │
                         ▼
                  FEATURE ENGINE
                         │
                         ▼
                    ML DATASET
                         │
                ┌────────┴────────┐
                ▼                 ▼
             TRAIN            EVALUATION
                │                 │
                ▼                 ▼
              MODEL          PERFORMANCE
                │
                ▼
          SYSTEM-1 DECISION
```

---

# 32. Dataset-to-Model Separation

The model must not depend on the raw dataset format.

For example:

```text
.GHC
XML
EVTX
Sysmon XML
JSON
CSV
```

are source representations.

The model should consume project-defined features derived from the canonical schema.

Therefore:

```text
RAW FORMAT ≠ CANONICAL EVENT ≠ FEATURE ≠ MODEL INPUT
```

This separation is a core architectural requirement.

---

# 33. Training Dataset Requirements

A dataset may be promoted to model training only when:

* provenance is complete
* schema version is known
* labels are documented
* leakage checks pass
* train/validation/test separation is defined
* class distribution is known
* missing-data rates are known
* parsing errors are measured
* reproducibility information exists
* licensing has been recorded

---

# 34. Evaluation Dataset Requirements

An evaluation dataset must remain as independent as reasonably possible from the data used to train the model.

The project should maintain a strict distinction between:

```text
development data
```

and:

```text
final evaluation data
```

Repeated tuning against the final test set effectively turns the test set into training data.

The final evaluation set should therefore be protected from routine model development.

---

# 35. Initial Dataset Roadmap

### Phase 1 — ADFA ingestion

```text
ADFA-WD
   ↓
parser
   ↓
canonical sequence representation
   ↓
statistics
   ↓
baseline classifier
```

### Phase 2 — ADFA evaluation

```text
ADFA-WD model
       ↓
ADFA-WD:SAA
       ↓
generalization analysis
```

### Phase 3 — Windows laboratory

```text
Windows 11 VM
       ↓
Sysmon + Windows Logs + PowerShell + Sensor
       ↓
collector
       ↓
canonical event dataset
```

### Phase 4 — Project-native model

```text
Windows 11 dataset
       ↓
feature engineering
       ↓
baseline ML
       ↓
calibration
       ↓
System-1 prototype
```

### Phase 5 — Cross-dataset evaluation

```text
ADFA-WD
AWSCTD
ADFA-WD:SAA
Windows 11 lab
       ↓
cross-source evaluation
```

---

# 36. What We Will Not Do

The project will not:

* force ADFA-WD into a fabricated EDR schema
* invent timestamps or process IDs
* train directly on attack-directory names
* randomly split individual sequence observations across partitions
* begin with a large neural network without a baseline
* treat model predictions as ground truth
* mix training and final evaluation data casually
* use an external dataset as a substitute for project-native telemetry
* claim that performance on ADFA-WD proves performance against a modern Windows endpoint
* treat a public benchmark as a production EDR dataset

---

# 37. Definition of Dataset Success

The dataset strategy is successful when the project can trace a model prediction backward through the entire data pipeline:

```text
MODEL PREDICTION
      ↓
FEATURE VECTOR
      ↓
CANONICAL EVENTS
      ↓
SOURCE EVENTS
      ↓
ORIGINAL DATA
```

and forward from a controlled experiment:

```text
EXPERIMENT
      ↓
KNOWN ACTIVITY
      ↓
TELEMETRY
      ↓
CANONICAL EVENTS
      ↓
FEATURES
      ↓
MODEL
      ↓
PREDICTION
```

Both directions must remain auditable.

---

# 38. Immediate Next Step

The next dataset task is **not model training**.

The next task is to define:

```text
WINDOWS-LAB-DATASET.md
```

This document will specify exactly how the Windows 11 laboratory will generate the project's canonical EDR telemetry.

It should define:

* VM configuration
* telemetry sources
* Sysmon configuration
* Windows event channels
* PowerShell logging
* sensor events
* event collection
* experiment identifiers
* benign scenarios
* suspicious scenarios
* attack simulations
* ground-truth procedure
* storage format
* dataset generation scripts
* validation checks

Once `WINDOWS-LAB-DATASET.md` is complete, the project can build the collection environment without guessing what data the model will eventually need.

---

# 39. Governing Principle

The AI-EDR dataset is not a single downloadable file.

It is a **versioned evidence pipeline**:

```text
SOURCE DATA
    ↓
SOURCE ADAPTER
    ↓
CANONICAL REPRESENTATION
    ↓
LABELED DATA
    ↓
FEATURE DATASET
    ↓
MODEL
    ↓
EVALUATION
```

ADFA-WD gives the project an immediate research starting point.

The Windows 11 laboratory gives the project the data required for the actual EDR.

The canonical schema connects the two.

The model must adapt to the evidence—not the other way around.
