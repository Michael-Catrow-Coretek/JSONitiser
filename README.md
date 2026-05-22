# JSONitizer (CYA Edition)

> **Because the LLM doesn't need to know who's about to get an HR violation.**

A stateless desktop utility for SOC analysts. Paste a raw Elastic JSON security alert, click **SANITIZE & CLEAN**, and get back a clean copy with all client-identifying data replaced by numbered placeholders — safe to hand to any LLM or share in a ticket. IP addresses are always preserved for threat-intelligence correlation.

---

## How It Works

JSONitizer uses two complementary techniques on every run:

### 1 — Structured Key Matching (ECS-Aware)

The engine recursively walks the JSON document, building the full dotted path as it descends (e.g. `_source → user → name` becomes `user.name`). When a path ends with a known sensitive Elastic Common Schema (ECS) field name, the value is swapped for a placeholder.

Matching uses **suffix logic** — `user.name` is caught whether it sits at the root of the document or buried five levels deep inside a `_source.winlog.event` wrapper. The `_source.*` and `fields.*` Kibana prefixes are therefore handled automatically.

### 2 — Regex Scanning (Unstructured Strings)

For fields not in the target key list (e.g. `process.command_line`, `message`, `event.reason`), the raw string value is scanned with a set of regular expressions that detect:

- Email addresses
- AD workstation hostnames (`WS-`, `LAPTOP-`, `DESKTOP-`, `PC-`)
- Windows user profile paths (`C:\Users\<username>\`)
- Windows Security Identifiers (`S-1-5-21-…`)
- NetBIOS `DOMAIN\username` patterns

### Stateless By Design

A **fresh engine instance** is created on every click of SANITIZE & CLEAN. No mapping is ever written to disk, no data persists between runs. The only place values exist is in the in-memory `mapping` dictionary that lives for the duration of that single click.

### Consistency Within a Run

The same raw value always maps to the same placeholder within one sanitisation run. If `jdoe` appears in `user.name`, in `process.command_line` as `CORP\jdoe`, and in `kibana.alert.workflow_user`, all three become `<USER_1>` — making the output coherent for LLM analysis.

---

## What Gets Sanitized

### Structured Key Targets

| Category | Placeholder | ECS / Elastic fields covered |
|---|---|---|
| **User** | `<USER_1>` … | `user.name`, `username`, `employee_id`, `full_name`, `last_name`, `user.id`, `user.full_name`, `user.last_name`, `winlog.user.name`, `source.user.name`, `destination.user.name`, `related.user` |
| **User** (Kibana) | `<USER_1>` … | `kibana.alert.workflow_user`, `kibana.alert.workflow_assignee_ids`, `kibana.alert.rule.created_by`, `kibana.alert.rule.updated_by` |
| **User** (M365) | `<USER_1>` … | `m365_defender.event.initiating_process.account_name`, `.account_sid`, `.logon_id` |
| **Email** | `<EMAIL_1>` … | `email`, `user.email`, `email_address` |
| **Host** | `<HOST_1>` … | `host.name`, `host.hostname`, `host.id`, `agent.name`, `agent.id`, `agent.ephemeral_id`, `elastic_agent.id`, `related.hosts` |
| **Org** | `<ORG_1>` … | `organization.name`, `user.domain`, `m365_defender.event.tenant.name`, `.tenant.id`, `.machine_group`, `.account_domain`, `azure.eventhub`, `azure.consumer_group`, `data_stream.namespace`, `kibana.alert.original_data_stream.namespace` |
| **URL** | `<URL_1>` … | `kibana.alert.url`, `kibana.alert.rule.meta.kibana_siem_app_url` |

### Regex Targets (Unstructured Strings)

| Pattern | Example match | Replaced with |
|---|---|---|
| Email address | `jdoe@corp.com` | `<EMAIL_1>` |
| AD workstation hostname | `WS-12345`, `LAPTOP-ABCDE` | `<HOST_1>` |
| Windows user path | `C:\Users\jdoe\AppData\…` | `C:\Users\<USER_1>\AppData\…` |
| Windows SID | `S-1-5-21-123-456-789-1001` | `<USER_1>` |
| DOMAIN\username | `CORP\jdoe` | `<USER_1>` |

---

## What Is Always Preserved

| Field type | Examples | Reason |
|---|---|---|
| **IP addresses** | `source.ip`, `client.ip`, `destination.ip`, `server.ip`, `host.ip` | Threat-intelligence correlation requires real IPs |
| **Process/file metadata** | `process.name`, `process.hash.*`, `pe.company`, `event.action` | Technical artifacts, not client PII |
| **Numeric & boolean values** | `event.duration`, `risk_score`, `event.type` | Non-identifying |
| **Windows system accounts** | `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, `HKLM\…` | Built-in OS identities, not client-specific |

---

## Placeholder Examples

### Before (raw Elastic JSON)

```json
{
  "user": {
    "name": "jdoe",
    "domain": "CORP",
    "email": "jdoe@acme.com"
  },
  "host": {
    "name": "LAPTOP-4A2B3C",
    "hostname": "LAPTOP-4A2B3C",
    "id": "a1b2c3d4-dead-beef-cafe-000000000001"
  },
  "agent": {
    "name": "LAPTOP-4A2B3C",
    "id": "ea-guid-0001"
  },
  "source": {
    "ip": "10.1.2.3"
  },
  "destination": {
    "ip": "185.220.101.47"
  },
  "process": {
    "command_line": "powershell.exe -File C:\\Users\\jdoe\\AppData\\Temp\\run.ps1",
    "executable": "C:\\Users\\jdoe\\AppData\\Temp\\run.ps1"
  },
  "m365_defender": {
    "event": {
      "tenant": { "name": "AcmeCorp" },
      "machine_group": "Workstations-EU",
      "initiating_process": {
        "account_name": "jdoe",
        "account_domain": "CORP",
        "account_sid": "S-1-5-21-111-222-333-1001"
      }
    }
  },
  "kibana": {
    "alert": {
      "workflow_user": "analyst1",
      "rule": {
        "created_by": "rule_author",
        "updated_by": "rule_editor"
      },
      "url": "https://kibana.acme.internal/app/security/alerts/xyz"
    }
  }
}
```

### After (sanitized output)

```json
{
  "user": {
    "name": "<USER_1>",
    "domain": "<ORG_1>",
    "email": "<EMAIL_1>"
  },
  "host": {
    "name": "<HOST_1>",
    "hostname": "<HOST_1>",
    "id": "<HOST_2>"
  },
  "agent": {
    "name": "<HOST_1>",
    "id": "<HOST_3>"
  },
  "source": {
    "ip": "10.1.2.3"
  },
  "destination": {
    "ip": "185.220.101.47"
  },
  "process": {
    "command_line": "powershell.exe -File C:\\Users\\<USER_1>\\AppData\\Temp\\run.ps1",
    "executable": "C:\\Users\\<USER_1>\\AppData\\Temp\\run.ps1"
  },
  "m365_defender": {
    "event": {
      "tenant": { "name": "<ORG_2>" },
      "machine_group": "<ORG_3>",
      "initiating_process": {
        "account_name": "<USER_1>",
        "account_domain": "<ORG_4>",
        "account_sid": "<USER_2>"
      }
    }
  },
  "kibana": {
    "alert": {
      "workflow_user": "<USER_3>",
      "rule": {
        "created_by": "<USER_4>",
        "updated_by": "<USER_5>"
      },
      "url": "<URL_1>"
    }
  }
}
```

> Note: `host.name` and `agent.name` both held `LAPTOP-4A2B3C` so both map to `<HOST_1>`. `host.id` is a different value, so it gets `<HOST_2>`.

### Placeholder Key Panel

After sanitisation, the amber panel at the bottom of the window shows the full reference table for that run:

```
  <EMAIL_1>         →   jdoe@acme.com
  <HOST_1>          →   LAPTOP-4A2B3C
  <HOST_2>          →   a1b2c3d4-dead-beef-cafe-000000000001
  <HOST_3>          →   ea-guid-0001
  <ORG_1>           →   CORP
  <ORG_2>           →   AcmeCorp
  <ORG_3>           →   Workstations-EU
  <ORG_4>           →   CORP
  <URL_1>           →   https://kibana.acme.internal/app/security/alerts/xyz
  <USER_1>          →   jdoe
  <USER_2>          →   S-1-5-21-111-222-333-1001
  <USER_3>          →   analyst1
  <USER_4>          →   rule_author
  <USER_5>          →   rule_editor
```

This lets you instantly decode any placeholder in the LLM response without leaving the app.

---

## GUI Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          JSONitizer                                     │
│         Because the LLM doesn't need to know who's about to …          │
├──────────────────────────────┬──────────────────────────────────────────┤
│  RAW ELASTIC JSON            │  SANITIZED OUTPUT  (IPs PRESERVED)      │
│                              │                                          │
│  [editable input]            │  [read-only green output]                │
│                              │                                          │
├──────────────────────────────┴──────────────────────────────────────────┤
│  PLACEHOLDER KEY                                                        │
│  [read-only amber reference table]                                      │
├─────────────────────────────────────────────────────────────────────────┤
│  [ SANITIZE & CLEAN ]  [ COPY TO CLIPBOARD ]  [ CLEAR ALL ]            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Getting Started

### Run the app

```powershell
uv run main.py
```

### Run the test suite

```powershell
uv run pytest tests/ -v
```

### Build a standalone .exe

```powershell
uv sync --group dev
uv run pyinstaller --onefile --windowed --name JSONitizer --icon assets\icon.ico main.py
```

The executable is written to `dist\JSONitizer.exe`. No Python installation required on the target machine.

---

## Project Structure

```
JSONitiser/
├── engine.py           # JSONitizerEngine — stateless sanitisation core
├── gui.py              # JSONitizerGUI — Tkinter dark-mode interface
├── main.py             # Entry point
├── tests/
│   └── test_engine.py  # Unit tests (engine only — no GUI dependency)
├── assets/             # App icons for packaging
├── pyproject.toml      # uv project config
├── STORE_SUBMISSION.md # Microsoft Store packaging & submission guide (local only)
└── .gitignore
```

---

## Requirements

- Python 3.10 or later
- No external runtime dependencies (stdlib only: `tkinter`, `json`, `re`)
- Dev tooling: `uv`, `pyinstaller`, `pytest` (all managed via `pyproject.toml`)
