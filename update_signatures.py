"""
update_signatures.py - Auto-fetch Technology Signatures

This script downloads the latest technology signatures from Wappalyzer's
open-source repository and converts them to our format.

Wappalyzer has 6,000+ technologies!

Usage:
    python update_signatures.py

Sources:
    - https://github.com/wappalyzer/wappalyzer
    - https://github.com/AliasIO/wappalyzer (mirror)
"""

import requests
import json
import os
import re
from pathlib import Path


# Wappalyzer's GitHub raw URLs for technology files
WAPPALYZER_URLS = [
    # Main categories (split into multiple files)
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/a.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/b.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/c.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/d.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/e.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/f.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/g.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/h.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/i.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/j.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/k.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/l.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/m.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/n.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/o.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/p.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/q.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/r.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/s.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/t.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/u.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/v.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/w.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/x.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/y.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/z.json",
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/technologies/_.json",
]

# Categories URL
CATEGORIES_URL = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/main/src/categories.json"


def fetch_json(url):
    """Fetch JSON from URL with error handling."""
    try:
        print(f"   Fetching: {url.split('/')[-1]}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"   ⚠️  Failed to fetch {url}: {e}")
        return None


def fetch_all_wappalyzer_signatures():
    """Download all Wappalyzer technology signatures."""
    print("\n📥 Downloading Wappalyzer signatures...\n")
    
    all_technologies = {}
    
    # Fetch each technology file
    for url in WAPPALYZER_URLS:
        data = fetch_json(url)
        if data:
            all_technologies.update(data)
    
    print(f"\n✅ Downloaded {len(all_technologies)} technologies!")
    return all_technologies


def fetch_categories():
    """Fetch category definitions."""
    print("\n📥 Downloading categories...")
    categories = fetch_json(CATEGORIES_URL)
    if categories:
        print(f"✅ Downloaded {len(categories)} categories!")
    return categories or {}


def convert_to_techscan_format(wappalyzer_techs, categories):
    """
    Convert Wappalyzer format to our TechScan format.
    
    Wappalyzer format:
    {
        "jQuery": {
            "cats": [59],
            "scriptSrc": ["jquery.*\\.js"],
            "js": {"jQuery.fn.jquery": ""},
            "website": "https://jquery.com"
        }
    }
    
    Our format:
    {
        "jquery": {
            "name": "jQuery",
            "category": "JavaScript libraries",
            "website": "https://jquery.com",
            "detection": {
                "scripts": ["jquery.*.js"],
                "html": [...]
            },
            "version_detection": {...}
        }
    }
    """
    print("\n🔄 Converting to TechScan format...")
    
    techscan_format = {"technologies": {}}
    
    for name, data in wappalyzer_techs.items():
        tech_id = name.lower().replace(' ', '_').replace('.', '_').replace('-', '_')
        
        # Get category name
        cat_ids = data.get('cats', [])
        category = "Unknown"
        if cat_ids and categories:
            cat_id = str(cat_ids[0])
            if cat_id in categories:
                category = categories[cat_id].get('name', 'Unknown')
        
        # Build detection rules
        detection = {}
        
        # Scripts (scriptSrc in Wappalyzer)
        if 'scriptSrc' in data:
            scripts = data['scriptSrc']
            if isinstance(scripts, str):
                scripts = [scripts]
            detection['scripts'] = scripts
        
        # HTML patterns
        if 'html' in data:
            html_patterns = data['html']
            if isinstance(html_patterns, str):
                html_patterns = [html_patterns]
            detection['html'] = html_patterns
        
        # Meta tags
        if 'meta' in data:
            detection['meta'] = data['meta']
        
        # Headers
        if 'headers' in data:
            detection['headers'] = data['headers']
        
        # Cookies
        if 'cookies' in data:
            detection['cookies'] = list(data['cookies'].keys()) if isinstance(data['cookies'], dict) else data['cookies']
        
        # CSS patterns
        if 'css' in data:
            css_patterns = data['css']
            if isinstance(css_patterns, str):
                css_patterns = [css_patterns]
            detection['css'] = css_patterns
        
        # DOM patterns
        if 'dom' in data:
            detection['dom'] = data['dom']
        
        # Only add if we have detection methods
        if detection:
            techscan_format['technologies'][tech_id] = {
                'name': name,
                'category': category,
                'website': data.get('website', ''),
                'detection': detection,
                'icon': data.get('icon', ''),
                'cpe': data.get('cpe', ''),  # For CVE matching!
            }
            
            # Version detection (from various sources)
            version_detection = {}
            
            # Version from scriptSrc regex
            if 'scriptSrc' in data:
                for pattern in (data['scriptSrc'] if isinstance(data['scriptSrc'], list) else [data['scriptSrc']]):
                    if '\\;version:\\' in pattern or ';version:' in pattern:
                        version_detection['script_filename'] = pattern.split(';version:')[0] if ';version:' in pattern else pattern
            
            # Version from meta
            if 'meta' in data:
                for meta_name, meta_pattern in data['meta'].items():
                    if '\\;version:\\' in str(meta_pattern):
                        version_detection['meta_' + meta_name] = meta_pattern
            
            # Version from headers
            if 'headers' in data:
                for header_name, header_pattern in data['headers'].items():
                    if '\\;version:\\' in str(header_pattern):
                        version_detection['header_' + header_name] = header_pattern
            
            if version_detection:
                techscan_format['technologies'][tech_id]['version_detection'] = version_detection
    
    print(f"✅ Converted {len(techscan_format['technologies'])} technologies!")
    return techscan_format


def save_signatures(data, output_path):
    """Save signatures to JSON file."""
    # Create directory if needed
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Saved to: {output_path}")


def update_signatures():
    """Main function to update signatures."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           🔄 TechScan Signature Updater                   ║
║                                                           ║
║   Fetching latest signatures from Wappalyzer (6000+ techs) ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Fetch data
    categories = fetch_categories()
    wappalyzer_techs = fetch_all_wappalyzer_signatures()
    
    if not wappalyzer_techs:
        print("❌ Failed to fetch signatures!")
        return False
    
    # Convert format
    techscan_data = convert_to_techscan_format(wappalyzer_techs, categories)
    
    # Save
    output_path = Path(__file__).parent / "signatures" / "technologies.json"
    save_signatures(techscan_data, output_path)
    
    # Also save raw Wappalyzer format for reference
    raw_output = Path(__file__).parent / "signatures" / "wappalyzer_raw.json"
    save_signatures(wappalyzer_techs, raw_output)
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ✅ Signatures Updated Successfully!                     ║
║                                                           ║
║   Technologies: {len(techscan_data['technologies']):,}                              ║
║   Source: Wappalyzer (GitHub)                             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    return True


if __name__ == "__main__":
    update_signatures()
