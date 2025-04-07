import json
import os
import glob

def validate_split_files():
    # Get all original files
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    original_files = glob.glob(os.path.join(data_dir, "nvdcve-1.1-20??.json"))
    
    print("Validating split JSON files...")
    
    for orig_file in original_files:
        base_name = os.path.splitext(os.path.basename(orig_file))[0]
        h1_file = os.path.join(data_dir, f"{base_name}-H1.json")
        h2_file = os.path.join(data_dir, f"{base_name}-H2.json")
        
        # Check if both split files exist
        if not os.path.exists(h1_file) or not os.path.exists(h2_file):
            print(f"ERROR: Missing split files for {base_name}")
            continue
        
        try:
            # Load all files
            with open(orig_file, 'r', encoding='utf-8') as f:
                orig_data = json.load(f)
            
            with open(h1_file, 'r', encoding='utf-8') as f:
                h1_data = json.load(f)
            
            with open(h2_file, 'r', encoding='utf-8') as f:
                h2_data = json.load(f)
            
            # Count CVEs
            orig_count = len(orig_data.get("CVE_Items", []))
            h1_count = len(h1_data.get("CVE_Items", []))
            h2_count = len(h2_data.get("CVE_Items", []))
            
            # Validate counts
            if orig_count != (h1_count + h2_count):
                print(f"ERROR: {base_name} count mismatch:")
                print(f"  Original: {orig_count}")
                print(f"  H1 + H2: {h1_count} + {h2_count} = {h1_count + h2_count}")
            else:
                print(f"PASSED: {base_name} - counts match:")
                print(f"  Original: {orig_count}")
                print(f"  H1: {h1_count} (Jan-Jun)")
                print(f"  H2: {h2_count} (Jul-Dec)")
                print(f"  Total: {h1_count + h2_count}")
            
            # Validate date ranges
            h1_dates = []
            h2_dates = []
            
            for cve in h1_data.get("CVE_Items", []):
                if "publishedDate" in cve:
                    h1_dates.append(cve["publishedDate"])
                    
            for cve in h2_data.get("CVE_Items", []):
                if "publishedDate" in cve:
                    h2_dates.append(cve["publishedDate"])
            
            # Sort dates
            h1_dates.sort()
            h2_dates.sort()
            
            # Print first and last dates for each file
            if h1_dates:
                print(f"  H1 date range: {h1_dates[0][:10]} to {h1_dates[-1][:10]}")
            if h2_dates:
                print(f"  H2 date range: {h2_dates[0][:10]} to {h2_dates[-1][:10]}")
            
            # Check for date consistency (all H1 dates should be before July, all H2 dates after June)
            h1_date_errors = sum(1 for date in h1_dates if date.startswith(f"{base_name[-4:]}-07") 
                                or date.startswith(f"{base_name[-4:]}-08")
                                or date.startswith(f"{base_name[-4:]}-09")
                                or date.startswith(f"{base_name[-4:]}-10")
                                or date.startswith(f"{base_name[-4:]}-11")
                                or date.startswith(f"{base_name[-4:]}-12"))
            
            h2_date_errors = sum(1 for date in h2_dates if date.startswith(f"{base_name[-4:]}-01")
                                or date.startswith(f"{base_name[-4:]}-02")
                                or date.startswith(f"{base_name[-4:]}-03")
                                or date.startswith(f"{base_name[-4:]}-04")
                                or date.startswith(f"{base_name[-4:]}-05")
                                or date.startswith(f"{base_name[-4:]}-06"))
            
            if h1_date_errors > 0 or h2_date_errors > 0:
                print(f"  WARNING: Date inconsistencies found:")
                print(f"    H1 entries with H2 dates: {h1_date_errors}")
                print(f"    H2 entries with H1 dates: {h2_date_errors}")
            else:
                print(f"  PASSED: All dates are in correct half-year files")
            
            # Check if any CVE IDs are duplicated across H1 and H2
            h1_ids = set()
            h2_ids = set()
            
            for cve in h1_data.get("CVE_Items", []):
                if "cve" in cve and "CVE_data_meta" in cve["cve"] and "ID" in cve["cve"]["CVE_data_meta"]:
                    h1_ids.add(cve["cve"]["CVE_data_meta"]["ID"])
            
            for cve in h2_data.get("CVE_Items", []):
                if "cve" in cve and "CVE_data_meta" in cve["cve"] and "ID" in cve["cve"]["CVE_data_meta"]:
                    h2_ids.add(cve["cve"]["CVE_data_meta"]["ID"])
            
            duplicate_ids = h1_ids.intersection(h2_ids)
            if duplicate_ids:
                print(f"  ERROR: Found {len(duplicate_ids)} CVE IDs that appear in both H1 and H2 files")
            else:
                print(f"  PASSED: No duplicate CVE IDs between H1 and H2 files")
            
            print("")
            
        except Exception as e:
            print(f"ERROR: Could not validate {base_name} - {str(e)}")

if __name__ == "__main__":
    validate_split_files()