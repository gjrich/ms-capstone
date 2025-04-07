# data_quality_enhancement.py
import sqlite3
import requests
import json
import logging
import sys
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_enhancement.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = 'data/vulnerability_analysis.db'

def identify_incomplete_records():
    """Identify CVE records with minimal information."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Find CVEs with minimal records (missing severity or CVSS score)
    cursor.execute('''
    SELECT cve_id 
    FROM vulnerabilities 
    WHERE description = 'Added from KEV catalog' 
       OR description = 'Added from EPSS data' 
       OR description = 'Added from Exploit-DB data'
       OR (cvss_v3_score IS NULL AND year IS NOT NULL)
    ''')
    
    incomplete_cves = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    logger.info(f"Found {len(incomplete_cves)} incomplete CVE records")
    return incomplete_cves

def enhance_cve_records(incomplete_cves, batch_size=50):
    """Enhance incomplete CVE records using external APIs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    enhanced_count = 0
    
    # Process in batches to avoid overwhelming APIs
    for i in range(0, len(incomplete_cves), batch_size):
        batch = incomplete_cves[i:i+batch_size]
        
        for cve_id in tqdm(batch, desc=f"Enhancing CVEs (batch {i//batch_size + 1}/{(len(incomplete_cves)-1)//batch_size + 1})"):
            try:
                # Try to fetch data from NVD API
                # Note: In a real implementation, you would need to handle API rate limits
                # and potentially use an API key for higher rate limits
                url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
                response = requests.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    cve_item = data.get('result', {}).get('CVE_Items', [])
                    
                    if cve_item:
                        item = cve_item[0]
                        
                        # Extract description
                        description = None
                        desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                        for desc in desc_data:
                            if desc.get('lang') == 'en':
                                description = desc.get('value')
                                break
                        
                        # Extract CVSS data
                        impact = item.get('impact', {})
                        base_metric_v3 = impact.get('baseMetricV3', {})
                        cvss_v3 = base_metric_v3.get('cvssV3', {})
                        
                        severity_v3 = base_metric_v3.get('baseSeverity')
                        cvss_v3_score = cvss_v3.get('baseScore')
                        cvss_v3_vector = cvss_v3.get('vectorString')
                        attack_vector = cvss_v3.get('attackVector')
                        attack_complexity = cvss_v3.get('attackComplexity')
                        
                        # Update the record in the database
                        cursor.execute('''
                        UPDATE vulnerabilities
                        SET description = ?,
                            severity_v3 = ?,
                            cvss_v3_score = ?,
                            cvss_v3_vector = ?,
                            attack_vector = ?,
                            attack_complexity = ?
                        WHERE cve_id = ?
                        ''', (
                            description if description else "No description available",
                            severity_v3,
                            cvss_v3_score,
                            cvss_v3_vector,
                            attack_vector,
                            attack_complexity,
                            cve_id
                        ))
                        
                        enhanced_count += 1
                        
            except Exception as e:
                logger.error(f"Error enhancing {cve_id}: {e}")
                continue
        
        # Commit after each batch
        conn.commit()
    
    conn.close()
    logger.info(f"Enhanced {enhanced_count} CVE records")
    return enhanced_count

def main():
    """Main function to enhance data quality."""
    logger.info("Starting data quality enhancement process...")
    
    # Identify incomplete records
    incomplete_cves = identify_incomplete_records()
    
    # Enhance CVE records
    if incomplete_cves:
        enhance_cve_records(incomplete_cves)
    
    logger.info("Data quality enhancement complete")

if __name__ == "__main__":
    main()