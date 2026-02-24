# MITRE ATT&CK Technique Extractor

A Python tool that extracts detailed MITRE ATT&CK technique information into individual JSON files using the official `mitreattack-python` library.

## Overview

This tool processes MITRE ATT&CK STIX JSON bundles and creates comprehensive, standalone JSON files for each technique. Unlike the simplified JSON tool, this extractor produces **detailed, reference-rich** files suitable for:

- Deep threat intelligence analysis
- Security research and documentation
- Building comprehensive knowledge bases
- Integration with security automation platforms
- Training and educational materials

## Features

- **Comprehensive Data Extraction**: Captures all technique metadata, relationships, and references
- **Official Library**: Uses the `mitreattack-python` library for reliable, standards-compliant parsing
- **Rich Context**: Includes tactics, platforms, data sources, mitigations, software, and subtechniques
- **Individual Files**: One JSON file per technique for easy access and version control
- **Full Metadata**: Preserves creation dates, versions, deprecation status, and external references
- **Relationship Mapping**: Links techniques to their parent/child techniques, mitigations, and software

## Installation

This tool requires the official MITRE ATT&CK Python library:

```bash
pip install mitreattack-python
```

## Usage

```bash
python3 extract_mitre.py --path <stix_file> --out <output_directory>
```

### Parameters

- `--path`: Path to MITRE ATT&CK STIX JSON bundle (default: `enterprise-attack.json`)
- `--out`: Output directory for technique files (default: `mitre/`)

### Example

```bash
python3 extract_mitre.py --path enterprise-attack-18.1.json --out techniques/
```

This will create individual JSON files like:
- `T1001_Data_Obfuscation.txt`
- `T1001_001_Junk_Data.txt`
- `T1003_OS_Credential_Dumping.txt`

## Input Format

Download official MITRE ATT&CK STIX JSON files from:
https://github.com/mitre/cti

Supported matrices:
- Enterprise ATT&CK
- Mobile ATT&CK
- ICS ATT&CK

## Output Format

Each technique is saved as a JSON file containing:

```json
{
  "technique_id": "T1001",
  "name": "Data Obfuscation",
  "description": "Adversaries may obfuscate command and control traffic...",
  "tactics": [
    {
      "id": "TA0011",
      "name": "Command and Control",
      "description": "The adversary is trying to communicate with compromised systems..."
    }
  ],
  "platforms": ["Linux", "macOS", "Windows"],
  "data_sources": [
    {
      "name": "Network Traffic: Network Traffic Content",
      "description": "Monitor and analyze network traffic..."
    }
  ],
  "mitigations": [
    {
      "id": "course-of-action--...",
      "name": "Network Intrusion Prevention",
      "description": "Use intrusion detection signatures...",
      "version": "1.0",
      "deprecated": false,
      "domains": ["enterprise-attack"],
      "external_references": [...],
      "created": "2019-06-11T17:26:48.127Z",
      "modified": "2023-03-30T21:01:42.677Z"
    }
  ],
  "software": [
    {
      "id": "malware--...",
      "external_id": "S0061",
      "name": "HDoor",
      "type": "malware",
      "description": "HDoor is malware...",
      "platforms": ["Windows"],
      "version": "2.0",
      "deprecated": false,
      "domains": ["enterprise-attack"],
      "external_references": [...],
      "created": "2017-05-31T21:32:01.612Z",
      "modified": "2023-03-26T19:27:12.227Z",
      "revoked": false
    }
  ],
  "references": [
    {
      "source": "University of Birmingham C2",
      "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
      "description": "Gardiner, J., Cova, M., Nagaraja, S. (2014, February)..."
    }
  ],
  "subtechniques": [
    {
      "id": "T1001.001",
      "name": "Junk Data",
      "description": "Adversaries may add junk data to protocols...",
      "platforms": ["Linux", "macOS", "Windows"],
      "tactics": [...]
    }
  ],
  "metadata": {
    "created": "2017-05-31T21:30:19.735Z",
    "modified": "2023-03-30T21:01:35.688Z",
    "version": "1.2",
    "deprecated": false,
    "is_subtechnique": false,
    "detection": "Analyze network data for uncommon data flows...",
    "domains": ["enterprise-attack"],
    "attack_spec_version": "3.1.0",
    "revoked": false
  }
}
```

## Use Cases

1. **Security Research**: Full technique details with all references and metadata
2. **Documentation**: Generate comprehensive technique reports
3. **Automation**: Integrate with SIEM, SOAR, or threat intelligence platforms
4. **Education**: Create training materials with complete context
5. **Version Control**: Track individual technique changes over time

## Requirements

- Python 3.6+
- `mitreattack-python` library

## Notes

- The tool excludes revoked and deprecated techniques by default
- Filenames are sanitized to remove special characters
- JSON output uses UTF-8 encoding and pretty printing
- Each file is standalone and can be used independently

## References

- [mitreattack-python Documentation](https://github.com/mitre-attack/mitreattack-python)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.0 Specification](https://oasis-open.github.io/cti-documentation/)
