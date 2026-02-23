import json
import sys
import os
import re

def build_nested_ai_kb(input_file):
    original_filename = os.path.basename(input_file)
    output_file = f"ai_{original_filename}"

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    print(f"Loading {input_file}...")
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    objects = data.get('objects', [])
    techniques_raw = {}
    software_raw = {}
    mitigations_raw = {}
    relationships = []

    def get_mitre_id(obj):
        for ref in obj.get('external_references', []):
            if ref.get('source_name') in ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']:
                return ref.get('external_id')
        return None

    def clean_desc(text):
        # Removes (Citation: ...) to significantly reduce token usage
        return re.sub(r'\(Citation:.*?\)', '', text).strip()

    print("Extracting core objects...")
    for obj in objects:
        stix_id = obj.get('id')
        obj_type = obj.get('type')

        if obj_type == 'relationship':
            relationships.append(obj)
            continue

        mitre_id = get_mitre_id(obj)
        if not mitre_id: continue

        # Capture revoked/deprecated statuses
        is_revoked = obj.get('revoked', False)
        is_deprecated = obj.get('x_mitre_deprecated', False)

        if obj_type == 'attack-pattern':
            techniques_raw[stix_id] = {
                "id": mitre_id,
                "name": obj.get('name', ''),
                "description": clean_desc(obj.get('description', '')),
                "tactics": [p.get('phase_name') for p in obj.get('kill_chain_phases', [])],
                "platforms": obj.get('x_mitre_platforms', []),
                "revoked": is_revoked,
                "deprecated": is_deprecated,
                "revoked_by": None, # Will be populated in the relationship pass
                "software": [],
                "mitigations": [],
                "sub_techniques": []
            }
        elif obj_type in ['malware', 'tool', 'intrusion-set']:
            software_raw[stix_id] = f"{mitre_id} ({obj.get('name', '')})"
        elif obj_type == 'course-of-action':
            mitigations_raw[stix_id] = f"{mitre_id} ({obj.get('name', '')})"

    print("Building physical hierarchy and resolving relationships...")
    child_stix_ids = set()
    
    # First pass: Nest Sub-techniques into Parents
    for rel in relationships:
        src, tgt = rel.get('source_ref'), rel.get('target_ref')
        rtype = rel.get('relationship_type')

        if rtype == 'subtechnique-of' and src in techniques_raw and tgt in techniques_raw:
            techniques_raw[tgt]["sub_techniques"].append(techniques_raw[src])
            child_stix_ids.add(src) 

    # Second pass: Resolve software, mitigations, and revoked-by mapping
    for rel in relationships:
        src, tgt = rel.get('source_ref'), rel.get('target_ref')
        rtype = rel.get('relationship_type')

        if rtype == 'uses' and src in software_raw and tgt in techniques_raw:
            if software_raw[src] not in techniques_raw[tgt]["software"]:
                techniques_raw[tgt]["software"].append(software_raw[src])
        elif rtype == 'mitigates' and src in mitigations_raw and tgt in techniques_raw:
            if mitigations_raw[src] not in techniques_raw[tgt]["mitigations"]:
                techniques_raw[tgt]["mitigations"].append(mitigations_raw[src])
        elif rtype == 'revoked-by' and src in techniques_raw and tgt in techniques_raw:
            # Map the old technique to the ID of the new technique that supersedes it
            techniques_raw[src]["revoked_by"] = techniques_raw[tgt]["id"]

    # Final Construction: Keep only Parent Techniques at the root level
    final_nested_kb = {}
    
    # Sort root-level techniques by MITRE ID
    sorted_root_techs = sorted(
        [t for sid, t in techniques_raw.items() if sid not in child_stix_ids], 
        key=lambda x: x['id']
    )

    for tech in sorted_root_techs:
        # Sort internal sub-techniques by their ID
        if tech["sub_techniques"]:
            tech["sub_techniques"] = sorted(tech["sub_techniques"], key=lambda x: x['id'])
        
        tech_id = tech.pop('id')
        final_nested_kb[tech_id] = tech

    print(f"Writing physically nested KB to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        # separators removes unnecessary spaces to save context tokens
        json.dump(final_nested_kb, f, separators=(',', ':'))
        
    print(f"Done! Sub-techniques are now physically nested under their parents.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <mitre_stix_file.json>")
    else:
        build_nested_ai_kb(sys.argv[1])