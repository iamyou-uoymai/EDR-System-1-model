# EVENT-SCHEMA.md

**Project:** AI-EDR
**Document:** Endpoint Event Schema
**Version:** 0.1
**Status:** Initial
**Primary benchmark:** ADFA-WD
**Secondary benchmark:** ADFA-WD:SAA
**Primary deployment target:** Windows
**Schema strategy:** Raw-source preservation + normalized event representation

---

# 1. Purpose

This document defines the event and telemetry schema used by the AI-EDR project.

The schema has two purposes:

1. Represent **ADFA-WD** data accurately enough to build the first machine-learning experiments.
2. Define a **future-proof normalized endpoint event format** for the eventual EDR sensor.

ADFA-WD is a Windows host-based intrusion-detection dataset provided by UNSW Canberra at ADFA. UNSW describes it as a dataset intended for evaluation of system-call-based HIDS and provides the **Full Process Traces** for download.

The dataset was collected from a **Windows XP SP2** environment and contains system-call traces associated with normal and attack activity. Published descriptions report that the dataset also contains process-oriented information such as process names, PIDs, and return values.

The schema therefore distinguishes between:

```text
RAW ADFA-WD DATA
        ↓
ADFA-WD PARSER
        ↓
NORMALIZED EVENT
        ↓
FEATURE ENGINE
        ↓
MODEL
```

---

# 2. Design Principles

## 2.1 Preserve the source

The original ADFA-WD information must never be discarded during ingestion.

The pipeline should retain:

* original file
* original trace
* original record/order
* source category
* source dataset
* source filename
* parser version

The normalized representation is derived data.

---

## 2.2 Separate source format from internal format

ADFA-WD is a historical benchmark.

The eventual EDR will collect modern Windows telemetry that may include:

* process creation
* process termination
* network connections
* files
* registry
* services
* scheduled tasks
* authentication
* PowerShell
* modules/DLLs
* security events

Therefore:

> **ADFA-WD is an input to the architecture, not the architecture itself.**

---

## 2.3 Events must be traceable

Every normalized event must be traceable back to its source.

```text
model prediction
      ↓
feature vector
      ↓
normalized event
      ↓
raw trace
      ↓
source file
```

This allows experiments to be reproduced.

---

## 2.4 Labels are metadata, not event fields

The observed behaviour and the ground-truth label should remain separate.

For example:

```text
event:
    process/system-call behaviour

label:
    attack
```

The event representation should not contain information that would only be available after classification.

This prevents accidental label leakage.

---

# 3. Data Layers

The data pipeline contains four principal representations.

```text
┌───────────────────────┐
│ 1. RAW SOURCE         │
│                       │
│ ADFA-WD original data │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ 2. PARSED EVENT       │
│                       │
│ Dataset-specific      │
│ representation        │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ 3. NORMALIZED EVENT   │
│                       │
│ Common AI-EDR schema  │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ 4. FEATURE RECORD     │
│                       │
│ ML-ready representation│
└───────────────────────┘
```

---

# 4. ADFA-WD Source Model

ADFA-WD is fundamentally a **host-based/system-call trace dataset**, rather than a modern multi-source EDR telemetry dataset.

Published descriptions identify information including:

* system-call sequences
* process names
* process identifiers (PIDs)
* return values

Other descriptions of the dataset characterize the Windows traces around DLL/function activity.

The first parser must therefore treat the ADFA-WD trace itself as the authoritative source representation.

---

# 5. Raw Event Representation

Every imported record must initially be represented as a raw object.

```json
{
  "source": {
    "dataset": "ADFA-WD",
    "file_name": "source_file",
    "partition": "training",
    "parser_version": "0.1.0"
  },

  "raw": {
    "record": "original source representation"
  }
}
```

No transformation should overwrite the raw value.

---

# 6. Dataset Partition

ADFA-WD separates normal training, normal validation, and attack traces. Published descriptions report:

* **355 normal training traces**
* **1,827 normal validation traces**
* **5,542 attack traces**

The attack traces are associated with multiple attack scenarios.

The schema therefore supports:

```text
training
validation
attack
```

as source-level dataset partitions.

## 6.1 Partition field

```json
{
  "dataset_partition": "training"
}
```

Allowed values:

```text
training
validation
attack
```

Important:

`dataset_partition` is **not** the same thing as the ML label.

---

# 7. Ground-Truth Label

The label is represented independently.

```json
{
  "label": {
    "class": "benign",
    "source": "dataset"
  }
}
```

Allowed initial classes:

```text
benign
malicious
```

For ADFA-WD:

```text
training     → benign
validation   → benign
attack       → malicious
```

This mapping is derived from the dataset's documented organization of normal and attack traces.

The normalized event itself must not contain a field such as:

```text
is_malicious = true
```

unless it exists explicitly in the **label layer**.

---

# 8. Event Identity

Every normalized event requires a unique internal identifier.

```json
{
  "event_id": "uuid"
}
```

The identifier must be unique within the local dataset.

Recommended fields:

```json
{
  "event_id": "uuid",
  "trace_id": "uuid",
  "event_sequence": 0
}
```

### Definitions

`event_id`

Unique identifier for a single normalized event.

`trace_id`

Identifier for the source trace from which the event originated.

`event_sequence`

The ordinal position of the event within the trace.

---

# 9. Trace Object

A trace represents the source-level behavioural sequence.

```json
{
  "trace_id": "uuid",

  "trace": {
    "dataset": "ADFA-WD",
    "partition": "training",
    "source_file": "example",
    "event_count": 1234
  }
}
```

The trace is important because many detection approaches rely on **sequences**, not isolated events.

Therefore the schema must support:

```text
event₁ → event₂ → event₃ → event₄ → ...
```

rather than treating every event as completely independent.

---

# 10. Process Context

Where process information is present in the source, it should be represented explicitly.

```json
{
  "process": {
    "name": "process.exe",
    "pid": 1234,
    "parent_pid": null
  }
}
```

### Fields

| Field          | Type         | Description                              |
| -------------- | ------------ | ---------------------------------------- |
| `name`         | string       | Process name                             |
| `pid`          | integer      | Process identifier                       |
| `parent_pid`   | integer/null | Parent process identifier when available |
| `path`         | string/null  | Executable path if available             |
| `command_line` | string/null  | Command line if available                |

ADFA-WD publications specifically identify process names and PIDs among the information associated with the traces.

Fields unavailable in ADFA-WD should remain `null`.

They must **not** be invented or reconstructed without evidence.

---

# 11. System-Call / API Activity

The most important ADFA-WD-specific portion of the schema is the observed system-call/API activity.

```json
{
  "activity": {
    "type": "system_call",
    "library": "example.dll",
    "function": "example_function",
    "identifier": "source-specific identifier",
    "return_value": "source-specific value"
  }
}
```

The exact parser representation must preserve the original identifier/function information as supplied by the source.

Because ADFA-WD is an older Windows host dataset, the raw representation should not be forcibly translated into modern Windows API names when such mapping is unavailable.

Published descriptions note DLL/function information and that ADFA-WD contains system-call-related traces.

---

# 12. Sequence Representation

The sequence must be retained separately from event-level attributes.

Example:

```json
{
  "sequence": {
    "position": 0,
    "length": 512,
    "previous_event_id": null,
    "next_event_id": "uuid"
  }
}
```

For example:

```text
Event 001
  ↓
Event 002
  ↓
Event 003
  ↓
Event 004
```

This is important because the first model will investigate whether **behavioural sequences** provide predictive information.

---

# 13. Temporal Representation

The ideal normalized schema contains timestamps:

```json
{
  "timestamp": "2026-09-23T00:00:00Z"
}
```

However, ADFA-WD does not provide modern EDR-grade temporal telemetry for every event in the same manner that our future sensor will.

Therefore:

```text
timestamp = null
```

is valid when unavailable.

The sequence position must not be incorrectly converted into a timestamp.

Instead:

```json
{
  "timestamp": null,
  "sequence": {
    "position": 42
  }
}
```

This explicitly distinguishes:

```text
time
```

from:

```text
order
```

---

# 14. Host Context

The eventual EDR requires endpoint identity.

```json
{
  "host": {
    "host_id": "host-001",
    "hostname": null,
    "os": {
      "family": "Windows",
      "version": null
    }
  }
}
```

For ADFA-WD:

```text
os.family = Windows
```

The dataset's collection environment is Windows XP SP2.

We should preserve the historical operating-system context rather than pretending the traces originated from modern Windows 10/11.

---

# 15. User Context

The normalized schema reserves space for user context.

```json
{
  "user": {
    "username": null,
    "sid": null,
    "integrity_level": null,
    "logon_session": null
  }
}
```

For ADFA-WD, unavailable fields remain:

```text
null
```

These fields are primarily for the future Windows 11 sensor.

---

# 16. Network Context

The future EDR schema supports network activity.

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

ADFA-WD should not be populated with fabricated network events where they are absent from the dataset.

---

# 17. File Context

Reserved for future endpoint telemetry:

```json
{
  "file": {
    "action": null,
    "path": null,
    "extension": null,
    "sha256": null
  }
}
```

Possible future `action` values:

```text
create
modify
rename
delete
read
execute
```

---

# 18. Registry Context

Reserved for Windows EDR telemetry:

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

This will not be populated from ADFA-WD unless the source explicitly provides the information.

---

# 19. Module / DLL Context

Because ADFA-WD includes Windows/DLL-related activity, modules are represented separately.

```json
{
  "module": {
    "name": null,
    "path": null,
    "base_address": null,
    "size": null
  }
}
```

A future sensor can extend this with:

```text
hash
signature
publisher
load_address
signed
```

---

# 20. Source Provenance

Every event must contain provenance.

```json
{
  "provenance": {
    "dataset": "ADFA-WD",
    "source_file": "file-name",
    "source_partition": "training",
    "source_record": 123,
    "parser_version": "0.1.0"
  }
}
```

This is mandatory.

The system must be able to answer:

> "Which original observation produced this training sample?"

---

# 21. Complete Normalized Event

The initial canonical event structure is:

```json
{
  "event_id": "uuid",
  "trace_id": "uuid",
  "event_sequence": 0,

  "timestamp": null,

  "host": {
    "host_id": "host-001",
    "hostname": null,
    "os": {
      "family": "Windows",
      "version": "Windows XP SP2"
    }
  },

  "process": {
    "name": null,
    "pid": null,
    "parent_pid": null,
    "path": null,
    "command_line": null
  },

  "user": {
    "username": null,
    "sid": null,
    "integrity_level": null,
    "logon_session": null
  },

  "activity": {
    "type": "system_call",
    "library": null,
    "function": null,
    "identifier": null,
    "return_value": null
  },

  "module": {
    "name": null,
    "path": null,
    "base_address": null,
    "size": null
  },

  "network": {
    "direction": null,
    "protocol": null,
    "source_ip": null,
    "source_port": null,
    "destination_ip": null,
    "destination_port": null
  },

  "file": {
    "action": null,
    "path": null,
    "extension": null,
    "sha256": null
  },

  "registry": {
    "action": null,
    "key": null,
    "value_name": null,
    "value_type": null,
    "value": null
  },

  "sequence": {
    "position": 0,
    "length": null,
    "previous_event_id": null,
    "next_event_id": null
  },

  "provenance": {
    "dataset": "ADFA-WD",
    "source_file": null,
    "source_partition": null,
    "source_record": null,
    "parser_version": "0.1.0"
  }
}
```

---

# 22. Label Object

Labels must be stored separately.

```json
{
  "label": {
    "class": "benign",
    "source": "ADFA-WD",
    "confidence": 1.0
  }
}
```

Initial values:

```text
benign
malicious
```

`confidence` refers to **ground-truth confidence**, not model confidence.

For ADFA-WD's dataset-defined normal/attack partition, this may initially be represented as:

```text
benign = 1.0
malicious = 1.0
```

because the label is inherited from the benchmark partition.

---

# 23. Model Output Object

Model predictions must also remain separate from ground truth.

```json
{
  "model_output": {
    "model_id": "edr-model-0.1.0",

    "classification": {
      "benign": 0.04,
      "malicious": 0.96
    },

    "severity": 8.1,

    "escalation_probability": 0.93
  }
}
```

This creates a clean separation:

```text
OBSERVATION
    ↓
GROUND TRUTH
    ↓
MODEL PREDICTION
```

---

# 24. Decision Object

The model prediction is not itself the operational decision.

```json
{
  "decision": {
    "action": "investigate",
    "reason": "threshold",
    "policy_version": "0.1.0"
  }
}
```

Possible initial actions:

```text
record
monitor
investigate
alert
```

Automatic endpoint containment is intentionally not part of the first version.

---

# 25. Feature Record

The feature layer converts normalized events into model-ready information.

Example:

```json
{
  "feature_record": {
    "event_id": "uuid",

    "features": {
      "process_name_id": 42,
      "activity_type_id": 7,
      "function_id": 193,
      "return_value_id": 2,

      "sequence_position": 41,
      "sequence_length": 512,

      "previous_activity_id": 8,
      "next_activity_id": 17
    }
  }
}
```

Feature engineering must be deterministic.

Given identical normalized input and the same feature-schema version:

```text
same event → same feature representation
```

---

# 26. Sequence Features

Because ADFA-WD is sequence-oriented, the first feature pipeline should preserve sequence information.

Potential representations include:

### Frequency

```text
count(function)
count(library)
count(return_value)
```

### N-grams

```text
system_call_1 → system_call_2
system_call_2 → system_call_3
```

### Sequence embeddings

Later experiments may represent a sequence as:

```text
token sequence
      ↓
embedding
      ↓
sequence encoder
      ↓
vector representation
```

### Windowed behaviour

```text
event[t-N : t]
```

This allows the model to reason about recent behavioural context rather than isolated calls.

---

# 27. Event Window

The model should eventually support a context window.

Example:

```text
Event 97
Event 98
Event 99
Event 100 ← current event
Event 101
```

For real-time inference, the primary form will be:

```text
previous N events + current event
```

Future investigation models may use larger windows.

---

# 28. Trace-Level Representation

For experiments where a complete trace is the prediction unit:

```json
{
  "trace_id": "uuid",

  "events": [
    {
      "event_sequence": 0
    },
    {
      "event_sequence": 1
    },
    {
      "event_sequence": 2
    }
  ],

  "label": {
    "class": "malicious"
  }
}
```

This allows us to compare:

```text
event-level classification
```

against:

```text
trace-level classification
```

---

# 29. ADFA-WD Attack Identity

The attack category should be stored as metadata when the source partition provides it.

Example:

```json
{
  "attack": {
    "present": true,
    "family": "source-defined attack category"
  }
}
```

The parser must preserve the dataset's original attack grouping.

It must not invent modern ATT&CK mappings.

MITRE ATT&CK mappings can be introduced later as a separate enrichment layer.

---

# 30. Preventing Data Leakage

The following fields must never be passed directly into the model as predictive features:

```text
dataset_partition
label.class
ground_truth
attack.present
attack.family
source_partition
```

These fields are metadata.

For example, this would be invalid:

```text
features = [
    syscall_sequence,
    process_name,
    dataset_partition
]
```

because:

```text
dataset_partition = attack
```

effectively reveals the answer.

Correct:

```text
features = [
    syscall_sequence,
    process_name
]
```

and separately:

```text
label = malicious
```

---

# 31. ADFA-WD Parser Contract

The parser must perform the following operations:

```text
1. Locate source file
2. Identify source partition
3. Preserve original content
4. Parse trace
5. Generate trace_id
6. Generate event_id
7. Preserve event order
8. Extract source-supported metadata
9. Create normalized events
10. Attach provenance
11. Attach ground-truth label
12. Validate schema
```

The parser must never silently drop an event.

Malformed records should be recorded in a parser-error structure.

---

# 32. Parser Error Object

```json
{
  "parse_error": {
    "source_file": "file",
    "source_record": 123,
    "error_type": "invalid_record",
    "message": "description",
    "raw_value": "original value"
  }
}
```

A parser error must never silently become a normal event.

---

# 33. Schema Validation

Every normalized event should pass structural validation.

Minimum requirements:

```text
event_id exists
trace_id exists
event_sequence exists
provenance exists
activity exists
```

Optional data may be:

```text
null
```

when unavailable.

---

# 34. Schema Versioning

The schema itself must be versioned.

Example:

```text
EVENT-SCHEMA v0.1
```

Each normalized event should contain:

```json
{
  "schema_version": "0.1"
}
```

If the schema later changes:

```text
0.2
0.3
1.0
```

old datasets must remain reproducible.

---

# 35. Relationship to the Future Windows EDR

The ADFA-WD schema intentionally represents only a subset of what the eventual sensor will collect.

```text
                 COMMON SCHEMA
                      │
        ┌─────────────┴──────────────┐
        ▼                            ▼
    ADFA-WD                    Windows 11 EDR
        │                            │
 system calls                  process events
 DLL/API data                  file events
 process metadata              registry events
                               network events
                               authentication
                               services
                               PowerShell
```

Both sources map into the same normalized representation.

This allows us to test:

```text
benchmark data
      ↓
model architecture
```

before collecting our own modern endpoint data.

---

# 36. What ADFA-WD Cannot Provide

The following fields should not be assumed to exist merely because they belong in the future schema:

```text
modern Windows version
full command line
modern process tree
network destination
file hash
registry path
user SID
integrity level
digital signature
parent/child relationships
fine-grained timestamps
```

Unavailable information remains:

```text
null
```

unless the parser can establish it from the actual source.

This limitation is important because ADFA-WD was created for system-call-based HIDS research rather than as a complete modern EDR telemetry corpus.

---

# 37. Dataset Strategy

The first dataset pipeline is:

```text
ADFA-WD Full Process Traces
             │
             ▼
       ADFA-WD Parser
             │
             ▼
       Raw Trace Store
             │
             ▼
      Normalized Events
             │
             ▼
        Feature Engine
             │
             ▼
       Model Training
```

ADFA-WD:SAA remains separate initially.

UNSW describes ADFA-WD:SAA as a stealth-attack addendum intended for evaluation in conjunction with ADFA-WD.

Therefore:

```text
ADFA-WD
    ↓
training / validation experiments

ADFA-WD:SAA
    ↓
secondary generalization evaluation
```

It should not automatically be merged into the initial training dataset.

---

# 38. First Model Input

The first experiment should not attempt to use every reserved schema field.

Initial input:

```text
system-call/API sequence
+
available process context
+
return-value information
```

Conceptually:

```text
┌─────────────────────────┐
│ ADFA-WD Trace            │
│                         │
│ activity₁               │
│ activity₂               │
│ activity₃               │
│ ...                     │
└───────────┬─────────────┘
            ↓
      Feature encoder
            ↓
      Model representation
            ↓
    System-1-style outputs
```

---

# 39. First Model Outputs

The first model should begin with a single primary decision:

```json
{
  "malicious_probability": 0.94
}
```

Once the baseline works, additional outputs can be introduced:

```json
{
  "malicious_probability": 0.94,
  "benign_probability": 0.06,
  "severity": 7.8,
  "escalation_probability": 0.91
}
```

Technique classification should be added only after the binary detection problem is properly understood.

---

# 40. Research Progression

The event schema supports this sequence:

```text
ADFA-WD
   ↓
Parsing
   ↓
Normalized traces
   ↓
Classical ML
   ↓
Sequence model
   ↓
Lightweight neural model
   ↓
Probability calibration
   ↓
System-1-style multi-output model
   ↓
ADFA-WD:SAA evaluation
   ↓
Modern Windows telemetry
   ↓
Actual EDR sensor
```

---

# 41. Example End-to-End Record

```json
{
  "schema_version": "0.1",

  "event_id": "8c51...",
  "trace_id": "b21d...",
  "event_sequence": 147,

  "timestamp": null,

  "host": {
    "host_id": "adfa-wd-host",
    "hostname": null,
    "os": {
      "family": "Windows",
      "version": "Windows XP SP2"
    }
  },

  "process": {
    "name": "source-process",
    "pid": 1234,
    "parent_pid": null,
    "path": null,
    "command_line": null
  },

  "activity": {
    "type": "system_call",
    "library": "source.dll",
    "function": "source_function",
    "identifier": "source_identifier",
    "return_value": "source_return_value"
  },

  "sequence": {
    "position": 147,
    "length": 512,
    "previous_event_id": "7a...",
    "next_event_id": "92..."
  },

  "provenance": {
    "dataset": "ADFA-WD",
    "source_file": "source_file",
    "source_partition": "attack",
    "source_record": 147,
    "parser_version": "0.1.0"
  }
}
```

Separate label:

```json
{
  "event_id": "8c51...",
  "label": {
    "class": "malicious",
    "source": "ADFA-WD"
  }
}
```

---

# 42. What This Schema Gives Us

This architecture deliberately gives us two compatible worlds.

### Benchmark world

```text
ADFA-WD
system-call traces
historical Windows environment
```

### EDR world

```text
modern endpoint sensor
multiple telemetry sources
real-time events
process/file/network/registry context
```

The normalized schema provides the bridge.

---

# 43. Initial Implementation Target

The first implementation should therefore contain only:

```text
/raw
    original ADFA-WD files

/parser
    ADFA-WD parser

/normalized
    canonical events

/labels
    ground truth

/features
    ML-ready representations
```

The initial model should consume:

```text
normalized ADFA-WD sequences
```

rather than directly accessing the raw files.

---

# 44. Non-Goals

This schema does not currently attempt to:

* force ADFA-WD into a modern EDR format
* fabricate missing Windows telemetry
* infer unavailable timestamps
* invent process relationships
* map every activity directly to ATT&CK
* embed model predictions into raw telemetry
* treat dataset labels as model features
* assume ADFA-WD represents modern Windows behaviour

---

# 45. Architectural Rule

The most important rule in this document is:

> **Raw telemetry is immutable evidence; normalized telemetry is a reproducible representation; features are derived data; model outputs are predictions; decisions are policy.**

The layers must remain separate.

```text
RAW
 ↓
NORMALIZED
 ↓
FEATURES
 ↓
MODEL
 ↓
DECISION
```

This separation is required for reproducibility, evaluation, calibration and eventual deployment.
