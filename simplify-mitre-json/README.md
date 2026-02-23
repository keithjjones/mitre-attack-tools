# MITRE ATT&CK JSON Simplifier

A Python tool that transforms MITRE ATT&CK STIX JSON data into a simplified, token-efficient format optimized for AI/LLM consumption.

## Overview

This tool processes the official MITRE ATT&CK STIX JSON files and creates a streamlined knowledge base that:

- **Nests sub-techniques** under their parent techniques (physical hierarchy)
- **Links software** (malware, tools, intrusion sets) to techniques
- **Links mitigations** to techniques
- **Removes citation references** to significantly reduce token usage
- **Tracks revoked/deprecated** techniques and their replacements
- **Outputs compact JSON** with minimal whitespace

## Why Use This Tool?

The official MITRE ATT&CK STIX JSON files are comprehensive but verbose, containing:
- Extensive citation references throughout descriptions
- Flat relationship structures requiring multiple lookups
- Metadata not always needed for AI reasoning

This tool creates a **context-optimized** version that maintains the critical information while reducing token count by ~40-60%, making it ideal for:
- AI/LLM knowledge bases
- RAG (Retrieval Augmented Generation) systems
- Context-limited API calls
- Efficient threat intelligence automation

## Usage

```bash
python simplify-mitre-json.py <mitre_stix_file.json>
```

### Example

```bash
python simplify-mitre-json.py enterprise-attack-18.1.json
```

This will generate `ai_enterprise-attack-18.1.json` with the simplified structure.

## Input Format

Download official MITRE ATT&CK STIX JSON files from:
https://github.com/mitre/cti

Supported matrices:
- Enterprise ATT&CK
- Mobile ATT&CK
- ICS ATT&CK

## Output Format

The output is a JSON object where each key is a MITRE technique ID, containing:

```json
{
  "T1001": {
    "name": "Data Obfuscation",
    "description": "Adversaries may obfuscate command and control traffic...",
    "tactics": ["command-and-control"],
    "platforms": ["Linux", "macOS", "Windows"],
    "revoked": false,
    "deprecated": false,
    "revoked_by": null,
    "software": ["S0061 (HDoor)", "S0385 (njRAT)"],
    "mitigations": ["M1031 (Network Intrusion Prevention)"],
    "sub_techniques": [
      {
        "id": "T1001.001",
        "name": "Junk Data",
        "description": "Adversaries may add junk data to protocols...",
        "tactics": ["command-and-control"],
        "platforms": ["Linux", "macOS", "Windows"],
        "revoked": false,
        "deprecated": false,
        "revoked_by": null,
        "software": [],
        "mitigations": [],
        "sub_techniques": []
      }
    ]
  }
}
```

## Key Features

### 1. Physical Nesting
Sub-techniques are embedded directly within their parent technique objects, eliminating the need for separate lookups.

### 2. Citation Removal
All `(Citation: ...)` references are stripped from descriptions, reducing token count while preserving the core technical content.

### 3. Revocation Tracking
Revoked and deprecated techniques include a `revoked_by` field pointing to the replacement technique ID.

### 4. Compact Output
JSON is written with minimal separators (`separators=(',', ':')`) to further reduce file size.

### 5. Sorted Output
Root-level techniques and sub-techniques are sorted by MITRE ID for consistent, predictable output.

## Data File Included

- `ai_enterprise-attack-18.1.json` - Pre-processed Enterprise ATT&CK v18.1 dataset

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## License

This tool processes publicly available MITRE ATT&CK data. MITRE ATT&CK is a trademark of The MITRE Corporation.

## Related Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [STIX 2.0 Specification](https://oasis-open.github.io/cti-documentation/)
