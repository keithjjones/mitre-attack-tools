# MITRE ATT&CK Tools

A collection of tools and utilities for working with MITRE ATT&CK framework data.

## Overview

This repository contains tools designed to process, transform, and optimize MITRE ATT&CK data for different use cases including threat intelligence, security automation, and AI/LLM integration.

Currently, there are two complementary tools available with plans to add more utilities as needed for various security and automation workflows.

## Tools

### [MITRE ATT&CK Technique Extractor](extract_mitre/)

Extracts detailed MITRE ATT&CK technique information into individual JSON files using the official `mitreattack-python` library.

**Key Features:**

- Comprehensive data extraction with full metadata
- Individual JSON file per technique
- Includes tactics, platforms, data sources, mitigations, and software
- Preserves all external references and citations
- Ideal for research, documentation, and integration

[Read more →](extract_mitre/README.md)

### [MITRE ATT&CK JSON Simplifier](simplify-mitre-json/)

Transforms official MITRE ATT&CK STIX JSON files into a simplified, token-efficient format optimized for AI/LLM consumption.

**Key Features:**

- Nests sub-techniques under parent techniques
- Links software and mitigations to techniques
- Removes citation references to reduce token usage by 40-60%
- Tracks revoked/deprecated techniques
- Outputs compact, sorted JSON
- No external dependencies

[Read more →](simplify-mitre-json/README.md)

## Tool Comparison

| Feature                  | extract_mitre                         | simplify-mitre-json                                |
| ------------------------ | ------------------------------------- | -------------------------------------------------- |
| **Output Format**        | Individual files per technique        | Single nested JSON file                            |
| **Detail Level**         | Comprehensive with full metadata      | Simplified, token-optimized                        |
| **File Size**            | Large (preserves all data)            | Compact (40-60% reduction)                         |
| **Citations**            | Preserved                             | Removed                                            |
| **Structure**            | Flat files with relationships         | Nested hierarchy (sub-techniques inside parents)   |
| **Dependencies**         | mitreattack-python                    | None (stdlib only)                                 |
| **Metadata**             | Full (timestamps, versions, domains)  | Essential only                                     |
| **External References**  | All references included               | Excluded for token efficiency                      |
| **Best For**             | Research, documentation, integration  | AI/LLM contexts, RAG systems                       |
| **Use When**             | You need complete technique details   | You need efficient AI consumption                  |

## Choosing the Right Tool

- **Use extract_mitre** for: Security research, comprehensive documentation, platform integration, training materials
- **Use simplify-mitre-json** for: AI/LLM knowledge bases, RAG systems, token-limited contexts, quick analysis

## About MITRE ATT&CK

MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

**Official Resources:**
- [MITRE ATT&CK Website](https://attack.mitre.org/)
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Getting Started

Each tool in this repository has its own README with detailed usage instructions. Navigate to the tool's directory for more information.

## Requirements

Tools in this repository are primarily written in Python 3.6+ and aim to minimize external dependencies where possible.

## Contributing

This repository is a collection of utilities for working with MITRE ATT&CK data. Tools are added as needed for various security and automation use cases.

## License

The code and tools in this repository are licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

**Important:** The MIT License applies only to the code in this repository. MITRE ATT&CK® data processed by these tools remains subject to MITRE's own terms of use. See [MITRE's Terms of Use](https://attack.mitre.org/resources/terms-of-use/) for details.

## Disclaimer

These tools process publicly available MITRE ATT&CK data. They are not affiliated with or endorsed by The MITRE Corporation. MITRE ATT&CK® is a trademark of The MITRE Corporation.
