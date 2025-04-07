import json
import os
from datetime import datetime

def split_nvd_file(file_path):
    # Load the JSON file
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract year from filename
    year = os.path.basename(file_path).split('-')[-1].split('.')[0]
    
    # Create containers for first and second half of the year
    h1_cves = {"CVE_Items": []}
    h2_cves = {"CVE_Items": []}
    
    # Copy metadata fields from original
    for key in data:
        if key != "CVE_Items":
            h1_cves[key] = data[key]
            h2_cves[key] = data[key]
    
    # Split CVEs by published date
    for cve_item in data["CVE_Items"]:
        # Extract published date
        published_date_str = cve_item.get("publishedDate", "")
        
        if published_date_str:
            published_date = datetime.strptime(published_date_str.split("T")[0], "%Y-%m-%d")
            
            # If month is 1-6, add to H1, else add to H2
            if published_date.month <= 6:
                h1_cves["CVE_Items"].append(cve_item)
            else:
                h2_cves["CVE_Items"].append(cve_item)
        else:
            # If no date is available, default to H1
            h1_cves["CVE_Items"].append(cve_item)
    
    # Get the full filename without extension
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    directory = os.path.dirname(file_path)
    
    # Create output filenames with full original name including year
    h1_filename = os.path.join(directory, f"{base_name}-H1.json")
    h2_filename = os.path.join(directory, f"{base_name}-H2.json")
    
    # Save the files
    with open(h1_filename, 'w', encoding='utf-8') as f:
        json.dump(h1_cves, f)
    
    with open(h2_filename, 'w', encoding='utf-8') as f:
        json.dump(h2_cves, f)
    
    print(f"Split {file_path} into:")
    print(f"  - {h1_filename} ({len(h1_cves['CVE_Items'])} CVEs)")
    print(f"  - {h2_filename} ({len(h2_cves['CVE_Items'])} CVEs)")

# List of files to process - using relative paths from script location
files_to_split = [
    "../data/nvdcve-1.1-2017.json",    
    "../data/nvdcve-1.1-2018.json",    
    "../data/nvdcve-1.1-2019.json",
    "../data/nvdcve-1.1-2020.json",
    "../data/nvdcve-1.1-2021.json",
    "../data/nvdcve-1.1-2022.json",
    "../data/nvdcve-1.1-2023.json",
    "../data/nvdcve-1.1-2024.json"
]

# Process each file
for file_path in files_to_split:
    # Convert relative path to absolute path
    abs_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), file_path))
    if os.path.exists(abs_file_path):
        print(f"Processing {abs_file_path}...")
        split_nvd_file(abs_file_path)
    else:
        print(f"File not found: {abs_file_path}")