#!/usr/bin/env python3
"""
MITRE ATT&CK technique extraction using the official mitreattack-python library.

Usage:
  python3 extract_mitre.py --path enterprise-attack.json --out mitre/
"""
import argparse
import json
import os
from typing import Any, Dict, List, Optional
from mitreattack.stix20 import MitreAttackData
from stix2 import MemoryStore


class MitreExtractorV2:
    """Extractor using official mitreattack-python library."""

    def __init__(self, stix_path: str):
        """Initialize with path to MITRE ATT&CK STIX bundle."""
        self.stix_path = stix_path

        # Load data into MemoryStore with allow_custom=True for v18+ compatibility
        with open(stix_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        src = MemoryStore(allow_custom=True)
        src.add(data['objects'])

        # Initialize MitreAttackData with the MemoryStore
        self.mitre = MitreAttackData(src=src)

    @staticmethod
    def convert_to_str(obj):
        """Convert STIX objects to JSON-serializable format."""
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return str(obj)

    @staticmethod
    def stix_to_dict(stix_obj):
        """Convert a STIX2 object to a plain dictionary."""
        if isinstance(stix_obj, dict):
            return stix_obj
        # STIX2 objects can be converted to dict using dict()
        return dict(stix_obj)

    def get_technique_data_sources(self, technique_stix_id: str) -> List[Dict[str, str]]:
        """Extract data sources for a technique via detection strategies."""
        data_sources = []

        # In v18+, detection is via detection strategies, not direct data sources
        detection_strategies = self.mitre.get_detection_strategies_detecting_technique(technique_stix_id)

        for entry in detection_strategies:
            ds = self.stix_to_dict(entry['object'])
            data_sources.append({
                'name': ds.get('name', 'Unknown'),
                'description': ds.get('description', '')[:200]  # Truncate long descriptions
            })

        return data_sources

    def format_technique_json(self, technique: Dict[str, Any]) -> str:
        """Format technique information as JSON."""
        # Convert STIX object to dict if needed
        technique_dict = self.stix_to_dict(technique)
        attack_id = self.mitre.get_attack_id(technique_dict['id'])

        # Extract tactics using library method (no manual parsing!)
        tactics = []
        for tactic_obj in self.mitre.get_tactics_by_technique(technique_dict['id']):
            tactic_dict = self.stix_to_dict(tactic_obj)
            tactic_attack_id = self.mitre.get_attack_id(tactic_dict['id'])
            tactics.append({
                'id': tactic_attack_id,
                'name': tactic_dict.get('name', ''),
                'description': tactic_dict.get('description', '')
            })

        # Build comprehensive technique data
        technique_data = {
            'technique_id': attack_id,
            'name': technique_dict.get('name', 'Unknown'),
            'description': technique_dict.get('description', ''),
            'tactics': tactics,
            'platforms': technique_dict.get('x_mitre_platforms', []),
            'data_sources': self.get_technique_data_sources(technique_dict['id']),
            'mitigations': [
                {
                    'id': mit_obj.get('id', ''),
                    'name': mit_obj.get('name', ''),
                    'description': mit_obj.get('description', ''),
                    'version': mit_obj.get('x_mitre_version', ''),
                    'deprecated': mit_obj.get('x_mitre_deprecated', False),
                    'domains': mit_obj.get('x_mitre_domains', []),
                    'external_references': [dict(ref) for ref in mit_obj.get('external_references', [])],
                    'created': self.convert_to_str(mit_obj.get('created', '')),
                    'modified': self.convert_to_str(mit_obj.get('modified', ''))
                }
                for mitigation in self.mitre.get_mitigations_mitigating_technique(technique_dict['id'])
                for mit_obj in [self.stix_to_dict(mitigation['object'])]
            ],
            'software': [
                {
                    'id': soft_obj.get('id', ''),
                    'external_id': self.mitre.get_attack_id(soft_obj['id']) if soft_obj.get('id') else '',
                    'name': soft_obj.get('name', ''),
                    'type': soft_obj.get('type', ''),
                    'description': soft_obj.get('description', ''),
                    'platforms': soft_obj.get('x_mitre_platforms', []),
                    'version': soft_obj.get('x_mitre_version', ''),
                    'deprecated': soft_obj.get('x_mitre_deprecated', False),
                    'domains': soft_obj.get('x_mitre_domains', []),
                    'external_references': [dict(ref) for ref in soft_obj.get('external_references', [])],
                    'created': self.convert_to_str(soft_obj.get('created', '')),
                    'modified': self.convert_to_str(soft_obj.get('modified', '')),
                    'revoked': soft_obj.get('revoked', False)
                }
                for software in self.mitre.get_software_using_technique(technique_dict['id'])
                for soft_obj in [self.stix_to_dict(software['object'])]
            ],
            'references': [
                {
                    'source': ref.get('source_name', ''),
                    'url': ref.get('url', ''),
                    'description': ref.get('description', '')
                }
                for ref in technique_dict.get('external_references', [])
                if ref.get('source_name') != 'mitre-attack'
            ],
            'subtechniques': [
                {
                    'id': self.mitre.get_attack_id(sub_obj.get('id')),
                    'name': sub_obj.get('name', ''),
                    'description': sub_obj.get('description', ''),
                    'platforms': sub_obj.get('x_mitre_platforms', []),
                    'tactics': [
                        {
                            'id': self.mitre.get_attack_id(self.stix_to_dict(tactic)['id']),
                            'name': self.stix_to_dict(tactic).get('name', ''),
                            'description': self.stix_to_dict(tactic).get('description', '')
                        }
                        for tactic in self.mitre.get_tactics_by_technique(sub_obj['id'])
                    ]
                }
                for subtech in self.mitre.get_subtechniques_of_technique(technique_dict['id'])
                for sub_obj in [self.stix_to_dict(subtech['object'])]
            ],
            'metadata': {
                'created': self.convert_to_str(technique_dict.get('created', '')),
                'modified': self.convert_to_str(technique_dict.get('modified', '')),
                'version': technique_dict.get('x_mitre_version', ''),
                'deprecated': technique_dict.get('x_mitre_deprecated', False),
                'is_subtechnique': technique_dict.get('x_mitre_is_subtechnique', False),
                'detection': technique_dict.get('x_mitre_detection', ''),
                'domains': technique_dict.get('x_mitre_domains', []),
                'attack_spec_version': technique_dict.get('x_mitre_attack_spec_version', ''),
                'revoked': technique_dict.get('revoked', False)
            }
        }

        # Add parent technique if this is a subtechnique
        if technique_dict.get('x_mitre_is_subtechnique', False):
            parent_entries = self.mitre.get_parent_technique_of_subtechnique(technique_dict['id'])
            if parent_entries and len(parent_entries) > 0:
                parent_dict = self.stix_to_dict(parent_entries[0]['object'])
                parent_attack_id = self.mitre.get_attack_id(parent_dict['id'])

                # Extract parent tactics using library method (no manual parsing!)
                parent_tactics = []
                for tactic_obj in self.mitre.get_tactics_by_technique(parent_dict['id']):
                    tactic_dict = self.stix_to_dict(tactic_obj)
                    tactic_attack_id = self.mitre.get_attack_id(tactic_dict['id'])
                    parent_tactics.append({
                        'id': tactic_attack_id,
                        'name': tactic_dict.get('name', ''),
                        'description': tactic_dict.get('description', '')
                    })

                technique_data['parent_technique'] = {
                    'id': parent_attack_id,
                    'name': parent_dict.get('name', ''),
                    'description': parent_dict.get('description', ''),
                    'platforms': parent_dict.get('x_mitre_platforms', []),
                    'tactics': parent_tactics
                }

        return json.dumps(technique_data, indent=2, ensure_ascii=False)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract MITRE ATT&CK techniques using mitreattack-python")
    ap.add_argument("--path", default="enterprise-attack.json", help="ATT&CK STIX bundle path")
    ap.add_argument("--out", default="mitre", help="Output directory for technique files")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"Error: STIX file not found: {args.path}")
        return 1

    # Create output directory
    os.makedirs(args.out, exist_ok=True)

    # Initialize extractor
    print("Loading MITRE ATT&CK data...")
    extractor = MitreExtractorV2(args.path)

    # Get all techniques
    techniques = extractor.mitre.get_techniques(remove_revoked_deprecated=True)

    # Process each technique
    technique_count = 0
    for technique in techniques:
        try:
            # Convert STIX object to dict
            tech_dict = dict(technique)
            attack_id = extractor.mitre.get_attack_id(tech_dict['id'])

            # Format the technique
            technique_json = extractor.format_technique_json(technique)

            # Create filename
            technique_name = tech_dict.get('name', 'Unknown')
            safe_name = technique_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
            safe_name = safe_name.replace(':', '_').replace('*', '_').replace('?', '_')
            safe_name = safe_name.replace('"', '_').replace('<', '_').replace('>', '_').replace('|', '_')
            safe_id = attack_id.replace('.', '_').replace('/', '_')
            filename = f"{safe_id}_{safe_name}.txt"
            filepath = os.path.join(args.out, filename)

            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(technique_json)

            technique_count += 1
            print(f"Extracted: {attack_id} -> {filename}")
        except Exception as e:
            print(f"Error processing technique: {e}")
            continue

    print(f"\nExtraction completed. {technique_count} techniques saved to {args.out}/")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
