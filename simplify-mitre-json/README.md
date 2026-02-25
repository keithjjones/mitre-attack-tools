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

### Examples

```bash
# Process Enterprise ATT&CK
python simplify-mitre-json.py enterprise-attack-18.1.json

# Process ICS ATT&CK
python simplify-mitre-json.py ics-attack-18.1.json

# Process Mobile ATT&CK
python simplify-mitre-json.py mobile-attack-18.1.json
```

This will generate `ai_<matrix>-attack-18.1.json` files with the simplified structure.

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

## Data Files Included

- `ai_enterprise-attack-18.1.json` - Pre-processed Enterprise ATT&CK v18.1 dataset (1.5MB)
- `ai_ics-attack-18.1.json` - Pre-processed ICS ATT&CK v18.1 dataset (120KB)
- `ai_mobile-attack-18.1.json` - Pre-processed Mobile ATT&CK v18.1 dataset (205KB)

## Example Use Case: Google Gemini Gem

One powerful application of this simplified JSON is using it as a knowledge base in a Google Gemini Gem. This allows you to create a custom AI assistant with up-to-date MITRE ATT&CK knowledge.

### Setting Up a MITRE ATT&CK Gem

1. Go to [gemini.google.com](https://gemini.google.com) and click on the Gem editor in the left sidebar
2. Choose which ATT&CK matrix to use (Enterprise, ICS, or Mobile) based on your needs
3. Create a new Gem and configure it with the following settings:

![Gemini Gem Setup](images/Mitre%20Gemini%20Gem.png)

**Gem Configuration:**

- **Name**: Mitre Att&ck Expert
- **Description**: A Mitre Att&ck Framework Expert
- **Instructions**:

  ```text
  You are a Mitre Att&ck framework expert, helping the user answer
  cybersecurity questions within its framework. All MITRE ATT&CK framework
  techniques are provided as a knowledge base in this chat. Use the
  knowledge base instead of your own, as it may be outdated.

  Do NOT make anything up. Use all of the MITRE ATT&CK data provided as a
  knowledge base in this Gemini Gem.
  ```

- **Knowledge**: Upload the JSON files (`ai_enterprise-attack-18.1.json`, `ai_ics-attack-18.1.json`, or `ai_mobile-attack-18.1.json`) directly in the Knowledge section of the Gem editor

### Using the Gem

Once configured, you can select the Gem from the Gem menu or the left-hand navigation bar (if recently used), then ask it specific MITRE ATT&CK questions and get accurate, up-to-date responses based on the knowledge base:

![Gemini Gem Output](images/Mitre%20Gemini%20Gem%20Output.png)

The Gem will answer questions about techniques, tactics, mitigations, and software using the current ATT&CK framework data, ensuring accuracy and relevance.

**Try it yourself**: [MITRE ATT&CK Expert Gem](https://gemini.google.com/gem/160eKB7Su6UTbiGgVU4hH4YtZ3lOyhgEo?usp=sharing) - A working example you can use or copy as a template for your own Gem.

### Why This Works

- **Token Efficiency**: The 40-60% size reduction means the entire ATT&CK framework fits comfortably within Gemini's knowledge limits
- **Up-to-Date**: Replace the JSON file whenever MITRE releases new versions
- **Accurate**: The Gem uses the provided data instead of potentially outdated training data
- **Comprehensive**: All techniques, sub-techniques, software, and mitigations are available for queries

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## License

This tool processes publicly available MITRE ATT&CK data. MITRE ATT&CK is a trademark of The MITRE Corporation.

## Related Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [STIX 2.0 Specification](https://oasis-open.github.io/cti-documentation/)
