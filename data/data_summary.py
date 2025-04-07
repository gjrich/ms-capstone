import pandas as pd
import json
import os
import glob
import numpy as np
import re
from datetime import datetime

def analyze_csv_file(file_path):
    """Analyze a CSV file and return key information about its structure and content."""
    print(f"\n{'='*80}\nAnalyzing CSV file: {os.path.basename(file_path)}\n{'='*80}")
    
    # Read CSV file
    df = pd.read_csv(file_path)
    
    # Basic information
    print(f"Number of records: {len(df)}")
    print(f"Number of columns: {len(df.columns)}")
    
    # Column information
    print("\nColumn information:")
    for col in df.columns:
        dtype = df[col].dtype
        missing = df[col].isna().sum()
        missing_percent = (missing / len(df)) * 100
        unique_count = df[col].nunique()
        unique_percent = (unique_count / len(df)) * 100
        
        sample_values = ""
        if not df[col].empty and not df[col].isna().all():
            non_null_values = df[col].dropna()
            if len(non_null_values) > 0:
                sample = non_null_values.sample(min(3, len(non_null_values))).tolist()
                sample_values = f", Sample values: {sample}"
        
        print(f"- {col}: Type={dtype}, Missing={missing} ({missing_percent:.2f}%), Unique values={unique_count} ({unique_percent:.2f}%){sample_values}")
    
    # Check for potential CVE IDs
    cve_columns = []
    for col in df.columns:
        # Check if column contains CVE IDs (CVE-YYYY-NNNNN format)
        if df[col].dtype == 'object':
            sample = df[col].dropna().sample(min(5, len(df[col].dropna()))).tolist() if not df[col].dropna().empty else []
            cve_pattern = any('CVE-' in str(val) for val in sample)
            if cve_pattern:
                cve_columns.append(col)
    
    if cve_columns:
        print("\nPotential CVE ID columns (for joining datasets):")
        for col in cve_columns:
            print(f"- {col}")
    
    # Check for date columns
    date_columns = []
    for col in df.columns:
        if df[col].dtype == 'object':
            # Check for common date patterns
            sample = df[col].dropna().sample(min(5, len(df[col].dropna()))).tolist() if not df[col].dropna().empty else []
            date_pattern = any(re.search(r'\d{4}-\d{2}-\d{2}', str(val)) for val in sample)
            if date_pattern:
                date_columns.append(col)
    
    if date_columns:
        print("\nPotential date columns:")
        for col in date_columns:
            print(f"- {col}")
    
    # Data quality issues
    print("\nPotential data quality issues:")
    issues_found = False
    
    # Check for high percentage of missing values
    high_missing = [col for col in df.columns if df[col].isna().mean() > 0.2]
    if high_missing:
        issues_found = True
        print(f"- Columns with >20% missing values: {high_missing}")
    
    # Check for columns with low cardinality relative to data size
    if len(df) > 10:  # Only check if we have enough data
        low_cardinality = [col for col in df.columns if 1 < df[col].nunique() < 5 and df[col].nunique() / len(df) < 0.01]
        if low_cardinality:
            issues_found = True
            print(f"- Columns with suspicious low cardinality: {low_cardinality}")
    
    # Check for columns with very high cardinality (potentially unique IDs)
    high_cardinality = [col for col in df.columns if df[col].nunique() / len(df) > 0.9 and df[col].nunique() > 10]
    if high_cardinality:
        issues_found = True
        print(f"- Columns with very high cardinality (potentially unique identifiers): {high_cardinality}")
    
    if not issues_found:
        print("- No major issues detected")
    
    # Sample data
    print("\nSample data (first 3 rows):")
    print(df.head(3).to_string())
    
    return df

def analyze_json_nvd_file(file_path):
    """Analyze an NVD JSON file and return key information about its structure and content."""
    print(f"\n{'='*80}\nAnalyzing NVD JSON file: {os.path.basename(file_path)}\n{'='*80}")
    
    # Read JSON file
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Basic information
    cve_items = data.get('CVE_Items', [])
    print(f"Number of CVE items: {len(cve_items)}")
    
    # Get global metadata if available
    for key in data:
        if key != 'CVE_Items':
            print(f"Global metadata - {key}: {data[key]}")
    
    # Analyze structure of the CVE items
    if cve_items:
        # Create a dictionary to count the presence of each field
        field_counts = {}
        field_types = {}
        nested_fields = {}
        
        # Analyze all items to get field statistics
        for item in cve_items:
            # First level keys
            for key in item:
                field_counts[key] = field_counts.get(key, 0) + 1
                if key not in field_types:
                    field_types[key] = type(item[key]).__name__
                
                # For nested objects, track their structure
                if isinstance(item[key], dict):
                    if key not in nested_fields:
                        nested_fields[key] = {}
                    
                    for subkey in item[key]:
                        nested_fields[key][subkey] = nested_fields[key].get(subkey, 0) + 1
        
        # Print field statistics
        print("\nField statistics (across all CVE items):")
        for key, count in field_counts.items():
            presence_percent = (count / len(cve_items)) * 100
            print(f"- {key}: Present in {count}/{len(cve_items)} items ({presence_percent:.2f}%), Type: {field_types.get(key, 'unknown')}")
        
        # Print nested field statistics for key structures
        print("\nNested field statistics:")
        for key, subfields in nested_fields.items():
            print(f"\n  {key} subfields:")
            for subkey, count in subfields.items():
                presence_percent = (count / field_counts[key]) * 100 if field_counts.get(key, 0) > 0 else 0
                print(f"  - {subkey}: Present in {count}/{field_counts.get(key, 0)} items ({presence_percent:.2f}%)")
    
        # Examine critical fields more deeply
        print("\nDetailed examination of important fields:")
        
        # Sample CVE IDs
        cve_ids = []
        for item in cve_items[:min(10, len(cve_items))]:
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A')
            cve_ids.append(cve_id)
        
        print(f"CVE IDs (sample): {cve_ids}")
        
        # Sample CVSS scores
        cvss_scores_v3 = []
        cvss_scores_v2 = []
        
        for item in cve_items[:min(10, len(cve_items))]:
            impact = item.get('impact', {})
            v3_score = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
            v2_score = impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 'N/A')
            
            cvss_scores_v3.append(v3_score)
            cvss_scores_v2.append(v2_score)
        
        print(f"CVSS v3 Scores (sample): {cvss_scores_v3}")
        print(f"CVSS v2 Scores (sample): {cvss_scores_v2}")
        
        # Sample dates
        published_dates = []
        last_modified_dates = []
        
        for item in cve_items[:min(10, len(cve_items))]:
            published = item.get('publishedDate', 'N/A')
            last_modified = item.get('lastModifiedDate', 'N/A')
            
            published_dates.append(published)
            last_modified_dates.append(last_modified)
        
        print(f"Published Dates (sample): {published_dates}")
        print(f"Last Modified Dates (sample): {last_modified_dates}")
        
        # References structure
        print("\nReference structure:")
        if cve_items and 'cve' in cve_items[0] and 'references' in cve_items[0]['cve']:
            ref_structure = cve_items[0]['cve']['references']
            print(f"Reference field structure: {ref_structure.keys() if isinstance(ref_structure, dict) else 'Not a dictionary'}")
            
            if isinstance(ref_structure, dict) and 'reference_data' in ref_structure:
                ref_data = ref_structure['reference_data']
                if ref_data and isinstance(ref_data, list) and len(ref_data) > 0:
                    print(f"Reference entry structure: {ref_data[0].keys() if isinstance(ref_data[0], dict) else 'Not a dictionary'}")
        
        # Configurations structure
        print("\nConfigurations structure:")
        if cve_items and 'configurations' in cve_items[0]:
            config = cve_items[0]['configurations']
            print(f"Configurations field structure: {config.keys() if isinstance(config, dict) else 'Not a dictionary'}")
    
    # Data quality issues
    print("\nPotential data quality issues:")
    issues_found = False
    
    # Check for missing CVE IDs
    missing_cve_ids = sum(1 for item in cve_items if not item.get('cve', {}).get('CVE_data_meta', {}).get('ID', ''))
    if missing_cve_ids > 0:
        issues_found = True
        print(f"- Missing CVE IDs: {missing_cve_ids} items ({missing_cve_ids/len(cve_items)*100:.2f}%)")
    
    # Check for missing CVSS scores
    missing_cvss_v3 = sum(1 for item in cve_items if 'baseMetricV3' not in item.get('impact', {}))
    if missing_cvss_v3 > 0:
        issues_found = True
        print(f"- Missing CVSS v3 scores: {missing_cvss_v3} items ({missing_cvss_v3/len(cve_items)*100:.2f}%)")
    
    if not issues_found:
        print("- No major issues detected")
    
    return data

def main():
    """Main function to analyze all data sources."""
    data_dir = 'data'
    
    # Analyze EPSS scores
    epss_file = os.path.join(data_dir, 'epss_scores-2025-03-30.csv')
    epss_df = analyze_csv_file(epss_file)
    
    # Analyze files exploits
    exploits_file = os.path.join(data_dir, 'files_exploits.csv')
    exploits_df = analyze_csv_file(exploits_file)
    
    # Analyze known exploited vulnerabilities (CSV)
    kev_file = os.path.join(data_dir, 'known_exploited_vulnerabilities.csv')
    kev_df = analyze_csv_file(kev_file)
    
    # Analyze just one NVD file (they all follow same schema)
    nvd_files = glob.glob(os.path.join(data_dir, 'nvdcve-1.1-*.json'))
    nvd_data = None
    
    if nvd_files:
        # Sample one file from each year to see any schema evolution
        years = set()
        sample_files = []
        
        for file in sorted(nvd_files):
            year = file.split('-')[-2][:4]
            if year not in years:
                years.add(year)
                sample_files.append(file)
        
        # Analyze the most recent file for detailed information
        newest_file = sorted(nvd_files)[-1]
        nvd_data = analyze_json_nvd_file(newest_file)
        
        # Report on file counts by year
        year_counts = {}
        for file in nvd_files:
            year = file.split('-')[-2][:4]
            year_counts[year] = year_counts.get(year, 0) + 1
        
        print("\nNVD file distribution by year:")
        for year, count in sorted(year_counts.items()):
            print(f"- {year}: {count} files")
    
    # Print summary addressing the four goals from the project plan
    print(f"\n{'='*80}\nData Understanding Goals Summary\n{'='*80}")
    
    # Goal 1: Review each data source structure in detail
    print("\n1. Data Source Structures:")
    print(f"- EPSS Scores ({os.path.basename(epss_file)}): {len(epss_df)} records, {len(epss_df.columns)} columns")
    print(f"  Primary purpose: Provides probability scores for vulnerability exploitation")
    
    print(f"\n- Exploit-DB ({os.path.basename(exploits_file)}): {len(exploits_df)} records, {len(exploits_df.columns)} columns")
    print(f"  Primary purpose: Contains information about publicly available exploits")
    
    print(f"\n- Known Exploited Vulnerabilities ({os.path.basename(kev_file)}): {len(kev_df)} records, {len(kev_df.columns)} columns")
    print(f"  Primary purpose: Lists vulnerabilities known to be actively exploited in the wild")
    
    print(f"\n- NVD Data ({len(nvd_files)} JSON files): Contains detailed vulnerability metadata")
    if nvd_data:
        cve_items = nvd_data.get('CVE_Items', [])
        print(f"  Sample file format: {len(cve_items)} CVE records with detailed metadata")
    print(f"  Primary purpose: Comprehensive vulnerability information source")
    
    # Goal 2: Document schema and available fields
    print("\n2. Key Fields and Schema Summary:")
    
    print("\nEPSS Scores key fields:")
    for col in epss_df.columns:
        print(f"- {col}: {epss_df[col].dtype}")
    
    print("\nExploit-DB key fields:")
    important_exploit_fields = ['id', 'file', 'description', 'date_published', 'author', 'type', 'platform', 'codes']
    for col in important_exploit_fields:
        if col in exploits_df.columns:
            print(f"- {col}: {exploits_df[col].dtype}")
    
    print("\nKnown Exploited Vulnerabilities key fields:")
    for col in kev_df.columns:
        print(f"- {col}: {kev_df[col].dtype}")
    
    print("\nNVD Data key fields:")
    if nvd_data and 'CVE_Items' in nvd_data and nvd_data['CVE_Items']:
        item = nvd_data['CVE_Items'][0]
        print("- cve.CVE_data_meta.ID: CVE identifier")
        print("- publishedDate: Date of vulnerability publication")
        print("- lastModifiedDate: Date of last modification")
        if 'impact' in item:
            impact = item['impact']
            if 'baseMetricV3' in impact:
                print("- impact.baseMetricV3.cvssV3: CVSS v3 scoring metrics")
            if 'baseMetricV2' in impact:
                print("- impact.baseMetricV2.cvssV2: CVSS v2 scoring metrics")
        print("- configurations: Information about affected products and versions")
    
    # Goal 3: Identify key fields for joining datasets
    print("\n3. Key Fields for Joining Datasets:")
    
    # Identify CVE ID fields in each dataset
    epss_cve_cols = [col for col in epss_df.columns if 'cve' in col.lower()]
    exploits_cve_cols = [col for col in exploits_df.columns if any(term in col.lower() for term in ['cve', 'vulnerability'])]
    kev_cve_cols = [col for col in kev_df.columns if 'cve' in col.lower()]
    
    print("The primary joining key across all datasets is the CVE ID:")
    print(f"- EPSS Scores: {epss_cve_cols if epss_cve_cols else 'CVE ID field not clearly identified'}")
    print(f"- Exploit-DB: {exploits_cve_cols if exploits_cve_cols else 'CVE ID field not clearly identified'}")
    print(f"- Known Exploited Vulnerabilities: {kev_cve_cols if kev_cve_cols else 'CVE ID field not clearly identified'}")
    print("- NVD Data: cve.CVE_data_meta.ID")
    
    print("\nSecondary joining fields (dates):")
    epss_date_cols = [col for col in epss_df.columns if any(term in col.lower() for term in ['date', 'time'])]
    exploits_date_cols = [col for col in exploits_df.columns if any(term in col.lower() for term in ['date', 'time'])]
    kev_date_cols = [col for col in kev_df.columns if any(term in col.lower() for term in ['date', 'time'])]
    
    print(f"- EPSS Scores: {epss_date_cols if epss_date_cols else 'Date fields not clearly identified'}")
    print(f"- Exploit-DB: {exploits_date_cols if exploits_date_cols else 'Date fields not clearly identified'}")
    print(f"- Known Exploited Vulnerabilities: {kev_date_cols if kev_date_cols else 'Date fields not clearly identified'}")
    print("- NVD Data: publishedDate, lastModifiedDate")
    
    # Goal 4: Assess data quality issues
    print("\n4. Data Quality Assessment:")
    
    print("\nEPSS Scores quality issues:")
    epss_missing = {col: epss_df[col].isna().sum() for col in epss_df.columns if epss_df[col].isna().sum() > 0}
    if epss_missing:
        print(f"- Missing values: {epss_missing}")
    else:
        print("- No missing values detected")
    
    print("\nExploit-DB quality issues:")
    exploits_missing = {col: exploits_df[col].isna().sum() for col in exploits_df.columns if exploits_df[col].isna().sum() > 0}
    print(f"- Missing values in key fields: {exploits_missing}")
    cve_id_present = any('CVE-' in str(val) for val in exploits_df.values.flatten() if isinstance(val, str))
    print(f"- CVE IDs present in data: {'Yes' if cve_id_present else 'No, may require text parsing'}")
    
    print("\nKnown Exploited Vulnerabilities quality issues:")
    kev_missing = {col: kev_df[col].isna().sum() for col in kev_df.columns if kev_df[col].isna().sum() > 0}
    if kev_missing:
        print(f"- Missing values: {kev_missing}")
    else:
        print("- No missing values detected")
    
    print("\nNVD Data quality issues:")
    if nvd_data and 'CVE_Items' in nvd_data:
        cve_items = nvd_data['CVE_Items']
        missing_cve_ids = sum(1 for item in cve_items if not item.get('cve', {}).get('CVE_data_meta', {}).get('ID', ''))
        print(f"- Missing CVE IDs: {missing_cve_ids} items")
        missing_cvss_v3 = sum(1 for item in cve_items if 'baseMetricV3' not in item.get('impact', {}))
        print(f"- Missing CVSS v3 scores: {missing_cvss_v3} items ({missing_cvss_v3/len(cve_items)*100:.2f}%)")
        missing_cvss_v2 = sum(1 for item in cve_items if 'baseMetricV2' not in item.get('impact', {}))
        print(f"- Missing CVSS v2 scores: {missing_cvss_v2} items ({missing_cvss_v2/len(cve_items)*100:.2f}%)")
    
    print("\nOverall Data Integration Challenges:")
    print("- CVE ID format consistency across datasets")
    print("- Date format standardization for temporal analysis")
    print("- Handling missing CVSS scores and metadata")
    print("- Extracting CVE IDs from Exploit-DB descriptions if needed")
    print("- Temporal alignment of vulnerability publication and exploitation data")
    
    print("\nNext Steps:")
    print("1. Create database schema based on identified fields")
    print("2. Design table relationships using CVE IDs as primary keys")
    print("3. Develop ETL process to load and transform the data")
    print("4. Create views for simplified analysis queries")

if __name__ == "__main__":
    main()