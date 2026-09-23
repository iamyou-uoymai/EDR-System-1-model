# EVENT-SCHEMA.md

**Project:** AI-EDR
**Document:** Endpoint Event and Trace Schema
**Version:** 0.2
**Status:** Initial implementation specification
**Primary benchmark:** ADFA-WD Full Process Traces
**Secondary benchmark:** ADFA-WD:SAA
**Target platform:** Windows
**Schema strategy:** Source-specific adapters → canonical representation → features → model

---

# 1. Purpose

This document defines how endpoint observations are represented throughout the AI-EDR project.

The schema has two related but distinct responsibilities:

1. Represent **ADFA-WD** accurately for the initial machine-learning research.
2. Define a **canonical telemetry model** that can later receive data from the project's own Windows EDR sensor.

These responsibilities must not be confused.

ADFA-WD is a historical Windows host-based intrusion-detection dataset intended for system-call-based HIDS evaluation. UNSW provides the **Full Process Traces** separately from the **ADFA-WD:SAA stealth-attack addendum**.

Therefore:

```text
                 SOURCE DATA
                     │
          ┌──────────┴──────────┐
          │                     │
      ADFA-WD              Future EDR
      adapter               sensor
          │                     │
          └──────────┬──────────┘
                     ▼
              CANONICAL MODEL
                     │
                     ▼
              FEATURE ENGINE
                     │
                     ▼
                  MODEL
                     │
                     ▼
                 DECISION
```

---

# 2. Core Principle

The most important rule is:

> **Do not force a dataset to contain telemetry that it does not actually provide.**

ADFA-WD observations must remain faithful to the source.

For example, if a trace contains a sequence of module/offset observations but no timestamp, network connection, command line, registry event, or file hash, the normalized representation must not invent those fields.

Unavailable information is represented as unavailable.

```text
available source information
        ↓
     preserve

unavailable information
        ↓
       null
```

---

# 3. Data Layers

The project uses five logical layers.

```text
┌───────────────────────────┐
│ 1. RAW SOURCE             │
│                           │
│ Original ADFA-WD / EDR    │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ 2. SOURCE REPRESENTATION  │
│                           │
│ ADFA-WD trace / EDR event │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ 3. CANONICAL REPRESENT.   │
│                           │
│ Common project schema     │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ 4. FEATURE REPRESENTATION │
│                           │
│ ML-ready data             │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ 5. MODEL / DECISION       │
│                           │
│ Prediction + policy       │
└───────────────────────────┘
```

---

# 4. Source Data Types

The initial project has two ADFA-WD-related source types.

## 4.1 ADFA-WD Full Process Traces

Primary research dataset.

The downloaded archive contains:

```text
Full_Process_Traces/
├── Full_Trace_Training_Data/
├── Full_Trace_Validation_Data/
└── Full_Trace_Attack_Data/
```

The project's inspected archive contains:

```text
Training traces:     355
Validation traces:  1,827
Attack traces:      5,542
```

These traces are represented as `.GHC` files.

The `.GHC` representation observed in the supplied archive consists primarily of ordered observations such as:

```text
ntdll.dll+0x16d33
ntdll.dll+0x16f03
ntdll.dll+0x1ce16
kernel32.dll+0x1bb9
...
```

Therefore the fundamental ADFA-WD object is:

> **an ordered behavioural trace sequence.**

---

# 5. ADFA-WD:SAA

ADFA-WD:SAA is treated as a separate source.

UNSW describes it as a **stealth attack addendum for evaluation in conjunction with ADFA-WD**.

It must not automatically be merged into the initial training set.

Initial strategy:

```text
ADFA-WD Full Process Traces
        ↓
initial training / validation

ADFA-WD:SAA
        ↓
later evaluation / generalization
```

The SAA source may contain richer process-oriented XML information than the `.GHC` traces.

That information must remain in its own source representation before any attempt is made to map it into the canonical schema.

---

# 6. Trace Is the Primary ADFA-WD Unit

For ADFA-WD, the primary analytical unit is:

```text
TRACE
```

rather than:

```text
individual EDR event
```

A trace is an ordered sequence:

```text
trace
│
├── observation 0
├── observation 1
├── observation 2
├── observation 3
├── ...
└── observation N
```

This distinction is fundamental to the first ML experiments.

---

# 7. ADFA-WD Source Trace Schema

Each ADFA-WD trace should initially be represented as:

```json
{
  "trace_id": "uuid",

  "source": {
    "dataset": "ADFA-WD",
    "format": "GHC",
    "partition": "training",
    "source_file": "filename.GHC"
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

This is the **source representation**.

It should remain as close as possible to the actual dataset.

---

# 8. Observation

An ADFA-WD observation is an element in a trace.

Initial representation:

```json
{
  "position": 147,
  "value": "kernel32.dll+0x1bb9"
}
```

Required fields:

| Field      | Type    | Description                |
| ---------- | ------- | -------------------------- |
| `position` | integer | Position within the trace  |
| `value`    | string  | Original observation value |

The original value must be preserved.

---

# 9. Token Representation

The `.GHC` observations can be treated as tokens.

For example:

```text
ntdll.dll+0x16d33
```

may be represented internally as:

```text
TOKEN
│
├── module = ntdll.dll
└── offset = 0x16d33
```

However, the parser must retain:

```text
raw_token = "ntdll.dll+0x16d33"
```

The project must not discard the original token after tokenization.

---

# 10. Token Object

A parsed token may therefore contain:

```json
{
  "position": 0,

  "raw": "ntdll.dll+0x16d33",

  "parsed": {
    "module": "ntdll.dll",
    "offset": "0x16d33"
  }
}
```

If parsing fails:

```json
{
  "position": 0,

  "raw": "unknown-source-value",

  "parsed": {
    "module": null,
    "offset": null
  }
}
```

The original value remains authoritative.

---

# 11. Trace Identity

Every trace receives an internal identifier.

```json
{
  "trace_id": "uuid"
}
```

The source filename must also be retained:

```json
{
  "source_file": "original-file-name.GHC"
}
```

The filename is provenance.

It should not automatically become an ML feature.

---

# 12. Trace Position

Because ADFA-WD does not provide modern event timestamps for these observations, sequence order is represented explicitly.

```json
{
  "position": 0
}
```

followed by:

```json
{
  "position": 1
}
```

and:

```json
{
  "position": 2
}
```

This means:

```text
position ≠ timestamp
```

Sequence order must never be converted into a fabricated timestamp.

---

# 13. Trace Length

Each trace should expose:

```json
{
  "trace_length": 22725
}
```

This is derived metadata.

It is useful for:

* dataset statistics
* sequence preprocessing
* batching
* model evaluation
* anomaly analysis

It should be calculated from the actual trace.

---

# 14. Dataset Partition

The source partition is represented separately:

```json
{
  "partition": "training"
}
```

Allowed values:

```text
training
validation
attack
```

These values describe the source organization.

They are not model predictions.

---

# 15. Ground Truth

Ground truth is stored separately from the observation sequence.

Initial binary classification:

```json
{
  "label": {
    "class": "benign",
    "source": "ADFA-WD"
  }
}
```

or:

```json
{
  "label": {
    "class": "malicious",
    "source": "ADFA-WD"
  }
}
```

Initial mapping:

```text
Full_Trace_Training_Data
        ↓
      benign

Full_Trace_Validation_Data
        ↓
      benign

Full_Trace_Attack_Data
        ↓
     malicious
```

This mapping follows the dataset's source organization.

---

# 16. Label Leakage Prevention

The following are **metadata**, not model features:

```text
partition
label.class
source_file
dataset name
attack directory name
attack family
trace identifier
```

For example, this is invalid:

```text
features = [
    syscall_sequence,
    partition
]
```

because:

```text
partition = attack
```

can reveal the answer.

Correct:

```text
features = [
    behavioural_sequence
]

label = malicious
```

---

# 17. Canonical Event Model

The eventual EDR will require a richer representation than ADFA-WD provides.

The canonical model therefore supports an event-oriented representation:

```json
{
  "event_id": "uuid",

  "trace_id": "uuid",

  "timestamp": null,

  "host": {},

  "process": {},

  "user": {},

  "activity": {},

  "file": {},

  "registry": {},

  "network": {},

  "module": {},

  "provenance": {}
}
```

However:

> **ADFA-WD does not need to populate every canonical field.**

---

# 18. Activity Object

The canonical activity object represents what the endpoint did.

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

This is preferable to prematurely calling every observation a modern Windows API event.

---

# 19. Process Context

The canonical schema reserves process context:

```json
{
  "process": {
    "name": null,
    "pid": null,
    "parent_pid": null,
    "path": null,
    "command_line": null
  }
}
```

For ADFA-WD:

```text
populate only if directly available from the relevant source
```

Otherwise:

```text
null
```

The project must not infer modern process metadata from a trace token.

---

# 20. Host Context

Canonical host information:

```json
{
  "host": {
    "host_id": null,

    "os": {
      "family": "Windows",
      "version": null
    }
  }
}
```

When the source explicitly identifies the collection environment, that information may be recorded as source metadata.

The eventual Windows EDR sensor will populate this with current endpoint information.

---

# 21. Timestamp

Canonical events support:

```json
{
  "timestamp": null
}
```

For ADFA-WD Full Process Traces:

```text
timestamp = null
```

unless an authoritative timestamp is present in the source being processed.

The parser must never generate timestamps from sequence position.

---

# 22. File Context

Reserved for future EDR telemetry:

```json
{
  "file": {
    "action": null,
    "path": null,
    "extension": null,
    "hash": null
  }
}
```

Possible future actions:

```text
create
modify
rename
delete
read
execute
```

ADFA-WD should not be populated with fabricated file events.

---

# 23. Registry Context

Reserved for future Windows telemetry:

```json
{
  "registry": {
    "action": null,
    "key": null,
    "value_name": null,
    "value_type": null,
    "value": null
  }
}
```

Possible actions:

```text
create
set
delete
rename
```

---

# 24. Network Context

Reserved for future endpoint telemetry:

```json
{
  "network": {
    "direction": null,
    "protocol": null,
    "source_ip": null,
    "source_port": null,
    "destination_ip": null,
    "destination_port": null
  }
}
```

No network information should be fabricated for ADFA-WD.

---

# 25. Module Context

The canonical model supports modules:

```json
{
  "module": {
    "name": null,
    "path": null,
    "base_address": null,
    "size": null,
    "hash": null,
    "signed": null
  }
}
```

For ADFA-WD, module information may be derived from an observation such as:

```text
ntdll.dll+0x16d33
```

but the parser must distinguish:

```text
observed module name
```

from:

```text
full module metadata
```

The latter must not be invented.

---

# 26. Sequence Context

Sequence information is first-class data.

```json
{
  "sequence": {
    "position": 147,
    "length": 512,

    "previous": null,
    "next": null
  }
}
```

For ADFA-WD, the minimum required fields are:

```text
position
length
```

The sequence itself remains the primary behavioural representation.

---

# 27. ADFA-WD Canonical Representation

After source parsing, an observation may become:

```json
{
  "schema_version": "0.2",

  "event_id": "uuid",
  "trace_id": "uuid",

  "sequence": {
    "position": 147,
    "length": 512
  },

  "activity": {
    "type": "system_call_sequence_observation",

    "raw_value": "ntdll.dll+0x16d33",

    "module": "ntdll.dll",

    "offset": "0x16d33"
  },

  "host": {
    "os": {
      "family": "Windows"
    }
  },

  "process": {
    "name": null,
    "pid": null,
    "parent_pid": null,
    "path": null,
    "command_line": null
  },

  "timestamp": null,

  "file": null,
  "registry": null,
  "network": null,

  "provenance": {
    "dataset": "ADFA-WD",
    "format": "GHC",
    "source_file": "example.GHC",
    "partition": "training",
    "parser_version": "0.1.0"
  }
}
```

This is a **canonical observation**, not a claim that ADFA-WD contains all of those fields.

---

# 28. Trace-Level Canonical Representation

For machine-learning experiments, the trace remains available as a first-class object.

```json
{
  "trace_id": "uuid",

  "observations": [
    {
      "position": 0,
      "activity": {}
    },
    {
      "position": 1,
      "activity": {}
    }
  ],

  "label": {
    "class": "benign"
  },

  "provenance": {
    "dataset": "ADFA-WD",
    "partition": "training"
  }
}
```

This allows both:

```text
trace-level models
```

and:

```text
observation/window-level models
```

to be tested.

---

# 29. Window Representation

The feature engine may construct behavioural windows:

```text
Observation 100
Observation 101
Observation 102
Observation 103
Observation 104
```

For example:

```json
{
  "window": {
    "trace_id": "uuid",
    "start_position": 100,
    "end_position": 104,
    "length": 5
  }
}
```

The window is derived data.

It must retain the source trace identity.

---

# 30. Token Vocabulary

The feature pipeline may create a vocabulary:

```text
TOKEN
  ↓
INTEGER ID
```

Example:

```text
ntdll.dll+0x16d33 → 184
ntdll.dll+0x16f03 → 57
kernel32.dll+0x1bb9 → 921
```

The vocabulary must be versioned.

```json
{
  "vocabulary_version": "0.1"
}
```

The original raw token must always remain recoverable.

---

# 31. Feature Representation

The feature engine transforms canonical observations into model input.

Possible initial representations:

### Token IDs

```text
[184, 57, 921, 57, 184]
```

### Frequency features

```text
token_frequency
module_frequency
sequence_length
unique_token_count
```

### N-grams

```text
token₁ → token₂
token₂ → token₃
```

### Sequence embeddings

Later:

```text
tokens
  ↓
embedding
  ↓
sequence encoder
  ↓
vector
```

The first experiments should compare simple approaches before assuming that a neural architecture is necessary.

---

# 32. Model Input Boundary

The model must consume:

```text
FEATURE REPRESENTATION
```

not:

```text
RAW DATASET
```

and not:

```text
GROUND TRUTH
```

Architecture:

```text
Raw .GHC
   ↓
Parser
   ↓
Canonical trace
   ↓
Feature engine
   ↓
Model input
   ↓
Model
```

---

# 33. Model Output

The initial model should produce a probability distribution.

```json
{
  "model_output": {
    "model_id": "edr-model-0.1.0",

    "classification": {
      "benign": 0.06,
      "malicious": 0.94
    }
  }
}
```

The probabilities must remain distinct from ground truth.

```text
ground truth:
    malicious

model:
    malicious = 0.94
```

---

# 34. Future System-1 Output

Once the binary detection baseline is established, the model can eventually produce:

```json
{
  "model_output": {
    "classification": {
      "benign": 0.06,
      "malicious": 0.94
    },

    "severity": 8.1,

    "escalation_probability": 0.92
  }
}
```

These are model outputs.

They are not part of the source event.

---

# 35. Decision Layer

The decision engine sits after the model.

```text
observation
     ↓
features
     ↓
model
     ↓
prediction
     ↓
decision policy
```

Example:

```json
{
  "decision": {
    "action": "investigate",
    "policy_version": "0.1.0"
  }
}
```

Initial actions:

```text
record
monitor
investigate
alert
```

The first implementation should not automatically perform destructive containment.

---

# 36. Provenance

Every canonical observation must identify where it originated.

Minimum provenance:

```json
{
  "provenance": {
    "dataset": "ADFA-WD",
    "format": "GHC",
    "source_file": "filename.GHC",
    "partition": "training",
    "parser_version": "0.1.0"
  }
}
```

This enables:

```text
prediction
   ↓
features
   ↓
canonical observation
   ↓
trace
   ↓
original source file
```

Reproducibility is a primary requirement.

---

# 37. Parser Errors

Invalid source data must not silently disappear.

```json
{
  "parse_error": {
    "source_file": "filename.GHC",
    "position": 147,
    "error_type": "invalid_observation",
    "message": "Unable to parse source value",
    "raw_value": "original value"
  }
}
```

The raw value must be preserved where possible.

---

# 38. Schema Versioning

Every canonical record contains:

```json
{
  "schema_version": "0.2"
}
```

Schema changes must be versioned.

Example:

```text
0.1
0.2
0.3
1.0
```

Existing datasets must remain reproducible after schema evolution.

---

# 39. ADFA-WD Adapter Boundary

The ADFA-WD parser should have a clearly defined boundary:

```text
                ADFA-WD
                   │
                   ▼
            ┌─────────────┐
            │ ADFA-WD     │
            │ ADAPTER     │
            └──────┬──────┘
                   │
                   ▼
           Canonical Trace
```

The adapter is responsible for:

* reading `.GHC` files
* preserving raw observations
* assigning trace identifiers
* preserving sequence order
* parsing module/offset structure where possible
* assigning source partition
* attaching ground truth
* attaching provenance
* reporting malformed records

The adapter must not:

* invent timestamps
* invent process IDs
* invent network connections
* invent file events
* invent registry events
* infer ATT&CK techniques
* insert model predictions

---

# 40. Future Windows EDR Adapter

The eventual Windows sensor will use a different source adapter.

```text
Windows endpoint
       ↓
Sensor
       ↓
Windows telemetry
       ↓
EDR adapter
       ↓
Canonical events
```

It may provide:

```text
process creation
process termination
command line
parent/child process
file activity
registry activity
network connections
authentication
PowerShell
services
modules
signatures
hashes
timestamps
users
integrity levels
```

Those capabilities belong to the future EDR telemetry source, not retroactively to ADFA-WD.

---

# 41. Source Adapters Are Independent

The architecture therefore becomes:

```text
                 ┌──────────────┐
                 │ ADFA-WD      │
                 │ .GHC         │
                 └──────┬───────┘
                        │
                 ADFA-WD adapter
                        │
                        ▼
                  ┌───────────┐
                  │           │
                  │ CANONICAL │
                  │   MODEL   │
                  │           │
                  └─────┬─────┘
                        ▲
                        │
                  EDR adapter
                        │
                 ┌──────┴───────┐
                 │ Windows      │
                 │ endpoint     │
                 └──────────────┘
```

This is the central architectural relationship.

---

# 42. ADFA-WD:SAA Adapter

SAA should receive its own adapter:

```text
ADFA-WD:SAA
     ↓
SAA adapter
     ↓
SAA source representation
     ↓
canonical representation
```

The SAA parser must preserve its XML structure before normalization.

This is especially important because the SAA material may contain process and module metadata that is not represented in the basic `.GHC` sequence format.

---

# 43. Training Dataset Separation

The initial experiment must maintain explicit dataset boundaries.

```text
ADFA-WD Training
       ↓
     TRAIN

ADFA-WD Validation
       ↓
   VALIDATION

ADFA-WD Attack
       ↓
   TEST / ATTACK
```

The exact experimental split will be defined in `DATASET.md`.

No random splitting of individual sequence tokens should be performed.

---

# 44. Sequence Leakage Prevention

A sequence must remain intact during dataset splitting.

Incorrect:

```text
trace A
 ├── part 1 → training
 └── part 2 → testing
```

Correct:

```text
trace A → one partition
```

This prevents information from the same behavioural trace appearing in both training and evaluation.

---

# 45. Attack-Family Metadata

Attack-family information may be retained as metadata where supplied by the dataset.

Example:

```json
{
  "attack_metadata": {
    "family": "source-defined category"
  }
}
```

However:

```text
attack_family
```

must not be used as a feature in the first binary detection model.

Later experiments may investigate:

```text
binary detection
        ↓
attack-family classification
        ↓
behaviour generalization
```

---

# 46. ATT&CK Mapping

The schema does not initially assign MITRE ATT&CK techniques to ADFA-WD observations.

Therefore:

```text
ATT&CK technique = null
```

unless a future research layer explicitly establishes and documents a mapping.

This avoids confusing:

```text
dataset ground truth
```

with:

```text
analyst interpretation
```

---

# 47. Initial ML Representation

The first model should operate primarily on:

```text
ADFA-WD sequence
```

Potential first representation:

```text
raw token
   ↓
vocabulary
   ↓
integer sequence
   ↓
sequence model
```

A baseline should also be constructed using simpler statistical features.

This gives us an empirical comparison between:

```text
classical ML
```

and:

```text
sequence/neural ML
```

---

# 48. Future EDR Representation

When the project moves from benchmark research to a real Windows endpoint:

```text
Windows telemetry
        ↓
canonical event
        ↓
temporal context
        ↓
behavioural window
        ↓
feature engine
        ↓
System-1 model
```

The canonical schema therefore acts as the bridge between:

```text
research dataset
```

and:

```text
real endpoint telemetry
```

---

# 49. What ADFA-WD Represents

ADFA-WD should be considered:

```text
SYSTEM-CALL / BEHAVIOURAL-SEQUENCE BENCHMARK
```

It should not be described as:

```text
complete modern EDR telemetry
```

It is valuable for:

* sequence modelling
* anomaly/detection research
* feature engineering
* baseline comparison
* probability calibration
* model experimentation
* benchmarking

It is insufficient by itself for validating a complete modern EDR sensor.

UNSW itself describes the ADFA datasets as datasets designed for system-call-based HIDS evaluation.

---

# 50. Schema Success Criteria

The schema is successful when:

1. Every source observation can be traced back to its original file.
2. Every trace has a stable internal identifier.
3. Sequence order is preserved.
4. Raw source values are preserved.
5. Dataset labels remain separate from features.
6. Missing telemetry is represented honestly.
7. ADFA-WD can feed the ML pipeline.
8. SAA can be evaluated independently.
9. Future Windows telemetry can use the same canonical representation.
10. Model outputs remain separate from observations.
11. Decisions remain separate from model predictions.
12. The entire pipeline can be reproduced from the original source data.

---

# 51. Final Architecture

The resulting data architecture is:

```text
                       RAW DATA
                          │
             ┌────────────┴────────────┐
             │                         │
        ADFA-WD .GHC              Future EDR
             │                     telemetry
             ▼                         │
      ADFA-WD Adapter             EDR Adapter
             │                         │
             └────────────┬────────────┘
                          ▼
                  CANONICAL DATA
                          │
                          ▼
                  SEQUENCE / EVENT
                       WINDOWS
                          │
                          ▼
                  FEATURE ENGINE
                          │
                          ▼
                     ML MODEL
                          │
                          ▼
                  MODEL OUTPUT
                          │
                          ▼
                  DECISION ENGINE
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
          RECORD                   INVESTIGATE
```

The governing rule remains:

> **Raw telemetry is immutable evidence. Source adapters interpret it. Canonical data standardizes it. Features transform it. Models predict from it. Policies make decisions from predictions.**

---

# 52. Immediate Implementation Target

The next implementation sequence is now fixed:

```text
EVENT-SCHEMA.md
      │
      ▼
DATASET.md
      │
      ▼
ADFA-WD parser
      │
      ▼
raw → parsed traces
      │
      ▼
dataset statistics
      │
      ▼
canonical representation
      │
      ▼
feature pipeline
      │
      ▼
baseline model
```

No neural architecture should be finalized before the baseline and dataset statistics have been established.
