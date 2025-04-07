# utils/create_database.py
import os
import json
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime
import re
import glob
import logging
from tqdm import tqdm
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database_creation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = os.path.join('data', 'vulnerability_analysis.db')

def create_database_schema():
    """Create the database schema with all required tables."""
    logger.info("Creating database schema...")
    
    # Connect to the database (will create it if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")
    
    # Create vulnerabilities table (core table)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        published_date TEXT,
        last_modified_date TEXT,
        description TEXT,
        severity_v3 TEXT,
        cvss_v3_score REAL,
        cvss_v3_vector TEXT,
        attack_vector TEXT,
        attack_complexity TEXT,
        privileges_required TEXT,
        user_interaction TEXT,
        scope TEXT,
        confidentiality_impact TEXT,
        integrity_impact TEXT,
        availability_impact TEXT,
        year INTEGER
    )
    ''')
    
    # Create CWE table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cwe (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        cwe_id TEXT,
        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
    )
    ''')
    
    # Create affected_products table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS affected_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT,
        cpe_uri TEXT,
        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
    )
    ''')
    
    # Create exploitations table (from KEV data)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS exploitations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added TEXT,
        date_known_exploited TEXT,
        short_description TEXT,
        required_action TEXT,
        due_date TEXT,
        known_ransomware_use TEXT,
        notes TEXT,
        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
    )
    ''')
    
    # Create epss_scores table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS epss_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        score_date TEXT,
        epss_score REAL,
        percentile REAL,
        model_version TEXT,
        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
    )
    ''')
    
    # Create public_exploits table (from Exploit-DB)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS public_exploits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        exploit_db_id INTEGER,
        file_path TEXT,
        description TEXT,
        date_published TEXT,
        author TEXT,
        type TEXT,
        platform TEXT,
        port INTEGER,
        date_added TEXT,
        verified INTEGER,
        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
    )
    ''')
    
    # Create analysis views
    
    # View for complete vulnerability info
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_vulnerability_complete AS
    SELECT 
        v.cve_id, 
        v.published_date,
        v.description,
        v.severity_v3,
        v.cvss_v3_score,
        v.attack_vector,
        v.attack_complexity,
        v.year,
        e.date_added AS exploitation_date_added,
        e.known_ransomware_use,
        MAX(s.epss_score) AS max_epss_score,
        CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_exploited,
        CASE WHEN p.cve_id IS NOT NULL THEN 1 ELSE 0 END AS has_public_exploit,
        CASE 
            WHEN e.date_added IS NOT NULL AND v.published_date IS NOT NULL
            THEN julianday(e.date_added) - julianday(v.published_date) 
            ELSE NULL 
        END AS days_to_exploitation,
        GROUP_CONCAT(DISTINCT cwe.cwe_id) AS cwe_ids,
        GROUP_CONCAT(DISTINCT ap.vendor || ':' || ap.product) AS affected_products
    FROM 
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    LEFT JOIN
        epss_scores s ON v.cve_id = s.cve_id
    LEFT JOIN
        public_exploits p ON v.cve_id = p.cve_id
    LEFT JOIN
        cwe ON v.cve_id = cwe.cve_id
    LEFT JOIN
        affected_products ap ON v.cve_id = ap.cve_id
    GROUP BY
        v.cve_id
    ''')
    
    # View for seasonal pattern analysis
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_seasonal_patterns AS
    SELECT
        strftime('%Y', v.published_date) AS year,
        strftime('%m', v.published_date) AS month,
        COUNT(v.cve_id) AS vulnerabilities_published,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS vulnerabilities_exploited,
        AVG(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) AS exploitation_rate,
        strftime('%Y-%m', v.published_date) || '-01' AS month_start_date,
        CASE 
            WHEN CAST(strftime('%m', v.published_date) AS INTEGER) IN (3, 6, 9, 12) THEN 1 
            ELSE 0 
        END AS is_quarter_end,
        CASE 
            WHEN CAST(strftime('%m', v.published_date) AS INTEGER) = 12 THEN 1 
            ELSE 0 
        END AS is_year_end,
        CASE 
            WHEN CAST(strftime('%m', v.published_date) AS INTEGER) IN (11, 12) THEN 1 
            ELSE 0 
        END AS is_holiday_season
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    GROUP BY
        year, month
    ORDER BY
        year, month
    ''')
    
    # View for critical patching window analysis
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_critical_patching_window AS
    SELECT
        v.cve_id,
        v.published_date,
        e.date_added AS exploitation_date,
        v.severity_v3,
        v.cvss_v3_score,
        v.attack_vector,
        v.attack_complexity,
        MAX(s.epss_score) AS max_epss_score,
        julianday(e.date_added) - julianday(v.published_date) AS days_to_exploitation,
        CASE 
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 7 THEN '0-7 days'
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 30 THEN '8-30 days'
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 90 THEN '31-90 days'
            ELSE '90+ days'
        END AS exploitation_window
    FROM
        vulnerabilities v
    JOIN
        exploitations e ON v.cve_id = e.cve_id
    LEFT JOIN
        epss_scores s ON v.cve_id = s.cve_id
    WHERE
        v.published_date IS NOT NULL AND
        e.date_added IS NOT NULL
    GROUP BY
        v.cve_id
    ''')
    
    # View for exploitation predictors
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_exploitation_predictors AS
    SELECT
        v.cve_id,
        v.severity_v3,
        v.cvss_v3_score,
        v.attack_vector,
        v.attack_complexity,
        v.privileges_required,
        v.user_interaction,
        v.scope,
        v.confidentiality_impact,
        v.integrity_impact,
        v.availability_impact,
        MAX(s.epss_score) AS max_epss_score,
        CASE WHEN p.cve_id IS NOT NULL THEN 1 ELSE 0 END AS has_public_exploit,
        CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_exploited,
        GROUP_CONCAT(DISTINCT cwe.cwe_id) AS cwe_ids,
        COUNT(DISTINCT ap.id) AS affected_product_count
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    LEFT JOIN
        epss_scores s ON v.cve_id = s.cve_id
    LEFT JOIN
        public_exploits p ON v.cve_id = p.cve_id
    LEFT JOIN
        cwe ON v.cve_id = cwe.cve_id
    LEFT JOIN
        affected_products ap ON v.cve_id = ap.cve_id
    GROUP BY
        v.cve_id
    ''')
    
    # View for COVID impact analysis
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_covid_impact AS
    SELECT
        v.cve_id,
        v.published_date,
        e.date_added AS exploitation_date,
        julianday(e.date_added) - julianday(v.published_date) AS days_to_exploitation,
        v.severity_v3,
        v.cvss_v3_score,
        CASE 
            WHEN v.published_date < '2020-03-01' THEN 'Pre-COVID'
            WHEN v.published_date >= '2020-03-01' AND v.published_date < '2021-06-01' THEN 'During-COVID'
            ELSE 'Post-COVID'
        END AS covid_period,
        CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_exploited
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        v.published_date IS NOT NULL
    ''')
    
    conn.commit()
    conn.close()
    
    logger.info("Database schema created successfully")

def extract_cve_ids_from_text(text):
    """Extract CVE IDs from text fields."""
    if not isinstance(text, str):
        return []
    
    # Pattern to match CVE IDs (CVE-YYYY-NNNNN)
    pattern = r'CVE-\d{4}-\d{1,7}'
    matches = re.findall(pattern, text)
    return matches

def load_nvd_data():
    """Load vulnerability data from NVD JSON files."""
    logger.info("Loading NVD data...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get list of NVD JSON files
    nvd_files = glob.glob(os.path.join('data', 'nvdcve-1.1-*.json'))
    
    total_cves = 0
    for nvd_file in tqdm(nvd_files, desc="Processing NVD files"):
        with open(nvd_file, 'r') as f:
            data = json.load(f)
        
        cve_items = data.get('CVE_Items', [])
        total_cves += len(cve_items)
        
        # Process each CVE item
        for item in tqdm(cve_items, desc=f"Processing {os.path.basename(nvd_file)}", leave=False):
            try:
                # Extract CVE ID
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    continue
                
                # Extract dates
                published_date = item.get('publishedDate')
                last_modified_date = item.get('lastModifiedDate')
                
                # Extract year from published date
                year = None
                if published_date:
                    match = re.search(r'(\d{4})', published_date)
                    if match:
                        year = int(match.group(1))
                
                # Extract description
                description = None
                desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                for desc in desc_data:
                    if desc.get('lang') == 'en':
                        description = desc.get('value')
                        break
                
                # Extract CVSS v3 data
                severity_v3 = None
                cvss_v3_score = None
                cvss_v3_vector = None
                attack_vector = None
                attack_complexity = None
                privileges_required = None
                user_interaction = None
                scope = None
                confidentiality_impact = None
                integrity_impact = None
                availability_impact = None
                
                impact = item.get('impact', {})
                base_metric_v3 = impact.get('baseMetricV3', {})
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                
                if cvss_v3:
                    severity_v3 = base_metric_v3.get('baseSeverity')
                    cvss_v3_score = cvss_v3.get('baseScore')
                    cvss_v3_vector = cvss_v3.get('vectorString')
                    attack_vector = cvss_v3.get('attackVector')
                    attack_complexity = cvss_v3.get('attackComplexity')
                    privileges_required = cvss_v3.get('privilegesRequired')
                    user_interaction = cvss_v3.get('userInteraction')
                    scope = cvss_v3.get('scope')
                    confidentiality_impact = cvss_v3.get('confidentialityImpact')
                    integrity_impact = cvss_v3.get('integrityImpact')
                    availability_impact = cvss_v3.get('availabilityImpact')
                
                # Insert into vulnerabilities table
                cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, published_date, last_modified_date, description,
                    severity_v3, cvss_v3_score, cvss_v3_vector,
                    attack_vector, attack_complexity, privileges_required,
                    user_interaction, scope, confidentiality_impact,
                    integrity_impact, availability_impact, year
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id, published_date, last_modified_date, description,
                    severity_v3, cvss_v3_score, cvss_v3_vector,
                    attack_vector, attack_complexity, privileges_required,
                    user_interaction, scope, confidentiality_impact,
                    integrity_impact, availability_impact, year
                ))
                
                # Extract and insert CWE data
                problem_type_data = item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
                for problem_type in problem_type_data:
                    for description in problem_type.get('description', []):
                        if description.get('lang') == 'en':
                            cwe_id = description.get('value')
                            if cwe_id and 'CWE-' in cwe_id:
                                cursor.execute('''
                                INSERT INTO cwe (cve_id, cwe_id)
                                VALUES (?, ?)
                                ''', (cve_id, cwe_id))
                
                # Extract and insert affected products data
                nodes = item.get('configurations', {}).get('nodes', [])
                for node in nodes:
                    process_node(cursor, node, cve_id)
                
                # Commit every 1000 CVEs to avoid large transactions
                if total_cves % 1000 == 0:
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Error processing CVE {cve_id}: {e}")
                continue
        
        # Commit after each file
        conn.commit()
    
    conn.close()
    logger.info(f"Loaded {total_cves} CVEs from NVD data")

def process_node(cursor, node, cve_id):
    """Process configuration node to extract affected products."""
    if 'cpe_match' in node:
        for cpe_match in node['cpe_match']:
            if cpe_match.get('vulnerable', False):
                cpe_uri = cpe_match.get('cpe23Uri')
                if cpe_uri:
                    # Parse CPE URI to extract vendor and product
                    parts = cpe_uri.split(':')
                    if len(parts) > 4:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else ''
                        
                        cursor.execute('''
                        INSERT INTO affected_products (cve_id, vendor, product, version, cpe_uri)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (cve_id, vendor, product, version, cpe_uri))
    
    # Process children nodes recursively
    if 'children' in node:
        for child in node['children']:
            process_node(cursor, child, cve_id)

def load_kev_data():
    """Load data from CISA Known Exploited Vulnerabilities (KEV) catalog."""
    logger.info("Loading KEV data...")
    
    kev_file = os.path.join('data', 'known_exploited_vulnerabilities.csv')
    if not os.path.exists(kev_file):
        logger.error(f"KEV file not found: {kev_file}")
        return
    
    df = pd.read_csv(kev_file)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if KEV data is already loaded
    cursor.execute("SELECT COUNT(*) FROM exploitations")
    count = cursor.fetchone()[0]
    if count > 0:
        logger.info("KEV data already loaded, truncating table...")
        cursor.execute("DELETE FROM exploitations")
    
    # Process and insert KEV data
    inserted = 0
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Loading KEV data"):
        try:
            cve_id = row['cveID']
            
            # Check if CVE exists in vulnerabilities table
            cursor.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone() is None:
                # Create a bare-minimum record in vulnerabilities table
                logger.warning(f"CVE {cve_id} not found in NVD data, creating minimal record")
                cursor.execute('''
                INSERT OR IGNORE INTO vulnerabilities (cve_id, description)
                VALUES (?, ?)
                ''', (cve_id, "Added from KEV catalog"))
            
            # Insert into exploitations table
            cursor.execute('''
            INSERT INTO exploitations (
                cve_id, vendor_project, product, vulnerability_name,
                date_added, date_known_exploited, short_description,
                required_action, due_date, known_ransomware_use, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                row.get('vendorProject', None),
                row.get('product', None),
                row.get('vulnerabilityName', None),
                row.get('dateAdded', None),
                None,  # No explicit exploitation date in KEV
                row.get('shortDescription', None),
                row.get('requiredAction', None),
                row.get('dueDate', None),
                row.get('knownRansomwareCampaignUse', None),
                row.get('notes', None)
            ))
            
            inserted += 1
            
        except Exception as e:
            logger.error(f"Error processing KEV entry for {cve_id}: {e}")
            continue
    
    conn.commit()
    conn.close()
    logger.info(f"Loaded {inserted} entries from KEV data")

def load_epss_data():
    """Load data from EPSS (Exploit Prediction Scoring System)."""
    logger.info("Loading EPSS data...")
    
    epss_file = os.path.join('data', 'epss_scores-2025-03-30.csv')
    if not os.path.exists(epss_file):
        logger.error(f"EPSS file not found: {epss_file}")
        return
    
    # The EPSS file seems to have an unusual format based on the data_summary output
    # We'll need to parse it carefully
    
    try:
        # First try standard parsing
        df = pd.read_csv(epss_file, low_memory=False)
        
        # Check if the file has correct headers
        if len(df.columns) < 2 or not any('model_version' in col for col in df.columns):
            # Try alternative parsing - assume first row contains headers
            df = pd.read_csv(epss_file, header=0, low_memory=False)
    except Exception as e:
        logger.error(f"Error parsing EPSS file: {e}")
        # Try with different encoding
        try:
            df = pd.read_csv(epss_file, encoding='latin1', low_memory=False)
        except Exception as e:
            logger.error(f"Failed to parse EPSS file with alternative encoding: {e}")
            return
    
    # Extract column names and data
    # From the data_summary, it looks like data might be in a format where column names are mixed up
    # We need to extract CVE IDs, scores, and dates
    
    # Try to identify which columns contain what
    cve_col = None
    score_col = None
    percentile_col = None
    model_version = None
    
    # Check if the first row might be column names
    if 'cve' in df.index.astype(str).tolist():
        # If 'cve' is in the index, the data might be transposed
        df = df.reset_index()
    
    # Try to find the CVE column
    for col in df.columns:
        if 'cve' in col.lower():
            cve_col = col
            break
    
    # If we can't find a clear CVE column, the first column might be it
    if cve_col is None and len(df.columns) > 0:
        if df.iloc[:, 0].astype(str).str.contains('CVE-').any():
            cve_col = df.columns[0]
    
    # Try to find the score and percentile columns
    for col in df.columns:
        if 'epss' in col.lower() or 'score' in col.lower():
            score_col = col
        elif 'percentile' in col.lower():
            percentile_col = col
        elif 'model' in col.lower() or 'version' in col.lower():
            model_version = col
    
    # If we still can't identify the columns clearly, try using column positions
    if cve_col is None and len(df.columns) > 0:
        cve_col = df.columns[0]
    if score_col is None and len(df.columns) > 1:
        score_col = df.columns[1]
    if percentile_col is None and len(df.columns) > 2:
        percentile_col = df.columns[2]
    
    # Extract model version if available
    if model_version is not None:
        model_version_value = df[model_version].iloc[0] if len(df) > 0 else None
    else:
        # Extract from column name if possible
        model_version_parts = [col for col in df.columns if 'model_version' in col.lower()]
        if model_version_parts:
            model_version_value = model_version_parts[0].split(':')[-1] if ':' in model_version_parts[0] else None
        else:
            model_version_value = None
    
    # Extract score date if available
    score_date_parts = [col for col in df.columns if 'score_date' in col.lower()]
    if score_date_parts:
        score_date = score_date_parts[0].split(':')[-1] if ':' in score_date_parts[0] else None
        if not score_date:
            score_date = datetime.now().strftime("%Y-%m-%d")
    else:
        # Extract from filename
        match = re.search(r'(\d{4}-\d{2}-\d{2})', os.path.basename(epss_file))
        score_date = match.group(1) if match else datetime.now().strftime("%Y-%m-%d")
    
    # Now we have identified the columns, let's process the data
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if EPSS data for this date is already loaded
    cursor.execute("SELECT COUNT(*) FROM epss_scores WHERE score_date = ?", (score_date,))
    count = cursor.fetchone()[0]
    if count > 0:
        logger.info(f"EPSS data for {score_date} already loaded, skipping...")
        conn.close()
        return
    
    # Process and insert EPSS data
    inserted = 0
    skipped = 0
    
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Loading EPSS data"):
        try:
            # Extract CVE ID
            if cve_col:
                cve_id = str(row[cve_col])
                if 'CVE-' not in cve_id:
                    # Might need to reconstruct the CVE ID
                    if cve_id.isdigit() or (cve_id.startswith('CAN-') or cve_id.startswith('CVE-')):
                        if cve_id.startswith('CAN-'):
                            cve_id = f"CVE-{cve_id[4:]}"
                        elif not cve_id.startswith('CVE-'):
                            # Try to construct a CVE ID from numeric format
                            cve_parts = cve_id.split('-')
                            if len(cve_parts) >= 2:
                                cve_id = f"CVE-{cve_parts[0]}-{cve_parts[1]}"
                            else:
                                logger.warning(f"Could not parse CVE ID from {cve_id}, skipping")
                                skipped += 1
                                continue
            else:
                logger.warning("No CVE column identified, skipping row")
                skipped += 1
                continue
            
            # Extract score and percentile
            if score_col:
                epss_score = row[score_col]
                if isinstance(epss_score, str):
                    try:
                        epss_score = float(epss_score)
                    except ValueError:
                        epss_score = None
            else:
                epss_score = None
            
            if percentile_col:
                percentile = row[percentile_col]
                if isinstance(percentile, str):
                    try:
                        percentile = float(percentile)
                    except ValueError:
                        percentile = None
            else:
                percentile = None
            
            # Check if CVE exists in vulnerabilities table
            cursor.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone() is None:
                # Create a bare-minimum record in vulnerabilities table
                cursor.execute('''
                INSERT OR IGNORE INTO vulnerabilities (cve_id, description)
                VALUES (?, ?)
                ''', (cve_id, "Added from EPSS data"))
            
            # Insert into epss_scores table
            cursor.execute('''
            INSERT INTO epss_scores (cve_id, score_date, epss_score, percentile, model_version)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                cve_id,
                score_date,
                epss_score,
                percentile,
                model_version_value
            ))
            
            inserted += 1
            
            # Commit every 10000 records to avoid large transactions
            if inserted % 10000 == 0:
                conn.commit()
            
        except Exception as e:
            logger.error(f"Error processing EPSS entry: {e}")
            skipped += 1
            continue
    
    conn.commit()
    conn.close()
    logger.info(f"Loaded {inserted} EPSS scores, skipped {skipped} entries")

def load_exploit_db_data():
    """Load data from Exploit-DB."""
    logger.info("Loading Exploit-DB data...")
    
    exploit_file = os.path.join('data', 'files_exploits.csv')
    if not os.path.exists(exploit_file):
        logger.error(f"Exploit-DB file not found: {exploit_file}")
        return
    
    df = pd.read_csv(exploit_file)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if Exploit-DB data is already loaded
    cursor.execute("SELECT COUNT(*) FROM public_exploits")
    count = cursor.fetchone()[0]
    if count > 0:
        logger.info("Exploit-DB data already loaded, truncating table...")
        cursor.execute("DELETE FROM public_exploits")
    
    # Process and insert Exploit-DB data
    inserted = 0
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Loading Exploit-DB data"):
        try:
            # Extract potential CVE IDs from 'codes' column
            cve_ids = []
            if pd.notna(row.get('codes')):
                cve_ids = extract_cve_ids_from_text(row['codes'])
            
            # If no CVE IDs in 'codes', try the description
            if not cve_ids and pd.notna(row.get('description')):
                cve_ids = extract_cve_ids_from_text(row['description'])
            
            # If still no CVE IDs, try other text fields
            if not cve_ids:
                for field in ['file', 'author', 'platform', 'application_url', 'source_url']:
                    if pd.notna(row.get(field)):
                        new_ids = extract_cve_ids_from_text(str(row[field]))
                        if new_ids:
                            cve_ids.extend(new_ids)
                            break
            
            # Make CVE IDs unique
            cve_ids = list(set(cve_ids))
            
            # If no CVE IDs found, insert with NULL cve_id
            if not cve_ids:
                cursor.execute('''
                INSERT INTO public_exploits (
                    cve_id, exploit_db_id, file_path, description, date_published,
                    author, type, platform, port, date_added, verified
                ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    int(row['id']) if pd.notna(row.get('id')) else None,
                    row.get('file') if pd.notna(row.get('file')) else None,
                    row.get('description') if pd.notna(row.get('description')) else None,
                    row.get('date_published') if pd.notna(row.get('date_published')) else None,
                    row.get('author') if pd.notna(row.get('author')) else None,
                    row.get('type') if pd.notna(row.get('type')) else None,
                    row.get('platform') if pd.notna(row.get('platform')) else None,
                    float(row['port']) if pd.notna(row.get('port')) else None,
                    row.get('date_added') if pd.notna(row.get('date_added')) else None,
                    int(row['verified']) if pd.notna(row.get('verified')) else 0
                ))
                inserted += 1
            else:
                # Insert an entry for each CVE ID
                for cve_id in cve_ids:
                    # Check if CVE exists in vulnerabilities table
                    cursor.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
                    if cursor.fetchone() is None:
                        # Create a bare-minimum record in vulnerabilities table
                        cursor.execute('''
                        INSERT OR IGNORE INTO vulnerabilities (cve_id, description)
                        VALUES (?, ?)
                        ''', (cve_id, "Added from Exploit-DB data"))
                    
                    # Insert into public_exploits table
                    cursor.execute('''
                    INSERT INTO public_exploits (
                        cve_id, exploit_db_id, file_path, description, date_published,
                        author, type, platform, port, date_added, verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        int(row['id']) if pd.notna(row.get('id')) else None,
                        row.get('file') if pd.notna(row.get('file')) else None,
                        row.get('description') if pd.notna(row.get('description')) else None,
                        row.get('date_published') if pd.notna(row.get('date_published')) else None,
                        row.get('author') if pd.notna(row.get('author')) else None,
                        row.get('type') if pd.notna(row.get('type')) else None,
                        row.get('platform') if pd.notna(row.get('platform')) else None,
                        float(row['port']) if pd.notna(row.get('port')) else None,
                        row.get('date_added') if pd.notna(row.get('date_added')) else None,
                        int(row['verified']) if pd.notna(row.get('verified')) else 0
                    ))
                    inserted += 1
            
            # Commit every 1000 records to avoid large transactions
            if inserted % 1000 == 0:
                conn.commit()
            
        except Exception as e:
            logger.error(f"Error processing Exploit-DB entry: {e}")
            continue
    
    conn.commit()
    conn.close()
    logger.info(f"Loaded {inserted} entries from Exploit-DB data")

def create_indexes():
    """Create indexes to optimize query performance."""
    logger.info("Creating database indexes...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create indexes on foreign keys
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe_cve_id ON cwe(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_affected_products_cve_id ON affected_products(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploitations_cve_id ON exploitations(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_scores_cve_id ON epss_scores(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_public_exploits_cve_id ON public_exploits(cve_id)")
    
    # Create indexes for common query patterns
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_year ON vulnerabilities(year)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_v3_score ON vulnerabilities(cvss_v3_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity_v3 ON vulnerabilities(severity_v3)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploitations_date_added ON exploitations(date_added)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_scores_score_date ON epss_scores(score_date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_scores_epss_score ON epss_scores(epss_score)")
    
    conn.commit()
    conn.close()
    
    logger.info("Database indexes created successfully")

def main():
    """Main function to create the database and load data."""
    logger.info("Starting database creation process...")
    
    # Create database schema
    create_database_schema()
    
    # Load data
    load_nvd_data()
    load_kev_data()
    load_epss_data()
    load_exploit_db_data()
    
    # Create indexes
    create_indexes()
    
    logger.info("Database creation complete")

if __name__ == "__main__":
    main()