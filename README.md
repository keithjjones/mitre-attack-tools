# MITRE ATT&CK Tools

A collection of tools and utilities for working with MITRE ATT&CK framework data.

## Overview

This repository contains tools designed to process, transform, and optimize MITRE ATT&CK data for different use cases including threat intelligence, security automation, and AI/LLM integration.

Currently, there is one tool available with plans to add more utilities as needed for various security and automation workflows.

## Tools

### [MITRE ATT&CK JSON Simplifier](simplify-mitre-json/)

Transforms official MITRE ATT&CK STIX JSON files into a simplified, token-efficient format optimized for AI/LLM consumption.

**Key Features:**
- Nests sub-techniques under parent techniques
- Links software and mitigations to techniques
- Removes citation references to reduce token usage by 40-60%
- Tracks revoked/deprecated techniques
- Outputs compact, sorted JSON

[Read more →](simplify-mitre-json/README.md)

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
