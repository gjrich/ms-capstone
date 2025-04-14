# data_quality_enhancement_improved.py
import sqlite3
import requests
import json
import logging
import sys
import time
import os
from tqdm import tqdm
import re

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

# API rate limits
# Without API key: 5 requests in 30 seconds (6 per minute)
# With API key: 50 requests in 30 seconds (100 per minute)
REQUEST_TIMEOUT = 10  # seconds

def get_api_key():
    """Get NVD API key securely from environment variable or user input."""
    # First check environment variable
    api_key = os.environ.get('NVD_API_KEY')
    
    # If not found in environment, prompt user
    if not api_key:
        print("\n============= NVD API KEY REQUIRED =============")
        print("To enhance CVE data, an NVD API key is strongly recommended.")
        print("Without a key, requests will be limited to 5 per 30 seconds (very slow).")
        print("Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key")
        print("=================================================\n")
        
        api_key = input("Enter your NVD API key (leave blank to continue without one): ").strip()
        
        # Ask if user wants to save it as environment variable for this session
        if api_key:
            save_key = input("Save this key as environment variable for this session? (y/n): ").strip().lower()
            if save_key.startswith('y'):
                os.environ['NVD_API_KEY'] = api_key
                print("Key saved as environment variable for this session (not stored on disk)")
    
    # Set the rate limit based on whether we have an API key
    global RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW
    if api_key:
        RATE_LIMIT_REQUESTS = 50  # With API key: 50 requests per 30 seconds
        RATE_LIMIT_WINDOW = 30
        logger.info("Using NVD API key - rate limit: 50 requests per 30 seconds")
    else:
        RATE_LIMIT_REQUESTS = 5   # Without API key: 5 requests per 30 seconds
        RATE_LIMIT_WINDOW = 30
        logger.info("No API key - rate limit: 5 requests per 30 seconds (this will be slow)")
    
    return api_key

def identify_incomplete_records(limit=None, filter_recent=True, min_year=2019):
    """Identify CVE records with minimal information.
    
    Args:
        limit: Maximum number of records to return
        filter_recent: If True, prioritize more recent CVEs
        min_year: Minimum year for CVEs if filter_recent is True
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Base query for incomplete records
    base_query = '''
    SELECT cve_id 
    FROM vulnerabilities 
    WHERE (description = 'Added from KEV catalog' 
       OR description = 'Added from EPSS data' 
       OR description = 'Added from Exploit-DB data'
       OR (cvss_v3_score IS NULL AND year IS NOT NULL))
    '''
    
    # Add year filtering if requested
    if filter_recent:
        base_query += f" AND (year IS NULL OR year >= {min_year})"
    
    # Add ordering to prioritize exploited vulnerabilities and more recent ones
    order_query = '''
    ORDER BY 
        CASE 
            WHEN cve_id IN (SELECT cve_id FROM exploitations) THEN 0 
            ELSE 1 
        END,
        year DESC NULLS LAST,
        cve_id DESC
    '''
    
    # Combine queries
    query = base_query + order_query
    
    # Add limit if specified
    if limit:
        query += f" LIMIT {limit}"
    
    cursor.execute(query)
    
    incomplete_cves = [row[0] for row in cursor.fetchall()]
    
    # Get the total count without the limit for reporting
    cursor.execute(f"SELECT COUNT(*) FROM ({base_query})")
    total_count = cursor.fetchone()[0]
    
    conn.close()
    
    logger.info(f"Found {len(incomplete_cves)} incomplete CVE records to process (out of {total_count} total)")
    
    # Log CVE year distribution
    if incomplete_cves:
        years = {}
        for cve in incomplete_cves:
            match = re.match(r'CVE-(\d{4})-', cve)
            if match:
                year = match.group(1)
                years[year] = years.get(year, 0) + 1
        
        logger.info("Distribution by year:")
        for year, count in sorted(years.items()):
            logger.info(f"  - {year}: {count} CVEs")
    
    return incomplete_cves

def verify_cve_batch(cve_batch, api_key=None):
    """Pre-check which CVEs exist in the NVD database using the CPE API.
    
    This is more efficient than checking one by one and helps avoid 404 errors.
    """
    valid_cves = []
    
    try:
        # Try to verify using the CPE API (more efficient)
        cve_list = ",".join(cve_batch)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_list}"
        
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            # Extract valid CVEs from the response
            returned_cves = [vuln['cve']['id'] for vuln in data.get('vulnerabilities', [])]
            valid_cves = returned_cves
            
            # Log invalid CVEs
            invalid_cves = set(cve_batch) - set(returned_cves)
            if invalid_cves:
                logger.debug(f"CVEs not found in NVD: {', '.join(invalid_cves)}")
        else:
            logger.warning(f"Error verifying CVE batch: HTTP {response.status_code}")
            # If verification fails, assume all CVEs are valid to try individually later
            valid_cves = cve_batch
            
    except Exception as e:
        logger.error(f"Error during batch verification: {e}")
        # If verification fails, assume all CVEs are valid to try individually later
        valid_cves = cve_batch
    
    return valid_cves

def enhance_cve_records(incomplete_cves, api_key=None, batch_size=None):
    """Enhance incomplete CVE records using external APIs with rate limiting."""
    if batch_size is None:
        batch_size = RATE_LIMIT_REQUESTS
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    enhanced_count = 0
    error_count = 0
    timeout_count = 0
    rate_limit_count = 0
    not_found_count = 0
    
    # Calculate total batches for progress reporting
    total_batches = (len(incomplete_cves) + batch_size - 1) // batch_size
    
    # Process in batches to respect API rate limits
    for i in range(0, len(incomplete_cves), batch_size):
        batch_start_time = time.time()
        batch = incomplete_cves[i:i+batch_size]
        batch_enhanced = 0
        
        logger.info(f"Processing batch {i//batch_size + 1}/{total_batches} ({len(batch)} CVEs)")
        
        # Pre-verify which CVEs exist
        valid_cves = verify_cve_batch(batch, api_key)
        
        not_found_count += len(batch) - len(valid_cves)
        
        if not valid_cves:
            logger.warning(f"No valid CVEs found in batch {i//batch_size + 1}")
            # Mark the non-existent CVEs as processed
            for cve_id in batch:
                cursor.execute('''
                UPDATE vulnerabilities
                SET description = 'CVE ID not found in NVD database'
                WHERE cve_id = ?
                ''', (cve_id,))
            conn.commit()
            continue
        
        # Process verified CVEs
        for cve_id in tqdm(valid_cves, desc=f"Batch {i//batch_size + 1}/{total_batches}"):
            try:
                # Use the newer NVD API (2.0) for better data
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                
                headers = {}
                if api_key:
                    headers['apiKey'] = api_key
                
                # Make request with timeout
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                
                # Handle rate limiting
                if response.status_code == 403:
                    logger.warning(f"Rate limit exceeded for {cve_id}")
                    rate_limit_count += 1
                    time.sleep(5)  # Wait a bit longer before next request
                    continue
                
                # Handle CVE not found
                if response.status_code == 404:
                    logger.warning(f"CVE {cve_id} not found in NVD database")
                    # Mark as not found
                    cursor.execute('''
                    UPDATE vulnerabilities
                    SET description = 'CVE ID not found in NVD database'
                    WHERE cve_id = ?
                    ''', (cve_id,))
                    not_found_count += 1
                    continue
                
                # Check for other errors
                if response.status_code != 200:
                    logger.warning(f"Error fetching {cve_id}: HTTP {response.status_code}")
                    error_count += 1
                    continue
                
                # Process successful response
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if vulnerabilities:
                    vuln = vulnerabilities[0]
                    cve_data = vuln.get('cve', {})
                    
                    # Extract description
                    description = None
                    descriptions = cve_data.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value')
                            break
                    
                    # Extract metrics
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
                    
                    if cvss_v3:
                        cvss_data = cvss_v3[0].get('cvssData', {})
                        base_score = cvss_data.get('baseScore')
                        severity = cvss_v3[0].get('baseSeverity')
                        vector = cvss_data.get('vectorString')
                        attack_vector = cvss_data.get('attackVector')
                        attack_complexity = cvss_data.get('attackComplexity')
                        privileges_required = cvss_data.get('privilegesRequired')
                        user_interaction = cvss_data.get('userInteraction')
                        scope = cvss_data.get('scope')
                        confidentiality_impact = cvss_data.get('confidentialityImpact')
                        integrity_impact = cvss_data.get('integrityImpact')
                        availability_impact = cvss_data.get('availabilityImpact')
                        
                        # Update the record in the database
                        cursor.execute('''
                        UPDATE vulnerabilities
                        SET description = ?,
                            severity_v3 = ?,
                            cvss_v3_score = ?,
                            cvss_v3_vector = ?,
                            attack_vector = ?,
                            attack_complexity = ?,
                            privileges_required = ?,
                            user_interaction = ?,
                            scope = ?,
                            confidentiality_impact = ?,
                            integrity_impact = ?,
                            availability_impact = ?
                        WHERE cve_id = ?
                        ''', (
                            description if description else "No description available",
                            severity,
                            base_score,
                            vector,
                            attack_vector,
                            attack_complexity,
                            privileges_required,
                            user_interaction,
                            scope,
                            confidentiality_impact,
                            integrity_impact,
                            availability_impact,
                            cve_id
                        ))
                    else:
                        # Update just the description if no CVSS data
                        cursor.execute('''
                        UPDATE vulnerabilities
                        SET description = ?
                        WHERE cve_id = ?
                        ''', (
                            description if description else "No description available",
                            cve_id
                        ))
                    
                    enhanced_count += 1
                    batch_enhanced += 1
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout fetching {cve_id}")
                timeout_count += 1
                continue
            except Exception as e:
                logger.error(f"Error enhancing {cve_id}: {e}")
                error_count += 1
                continue
        
        # Commit after each batch
        conn.commit()
        
        # Report progress for this batch
        batch_duration = time.time() - batch_start_time
        logger.info(f"Batch {i//batch_size + 1} complete: enhanced {batch_enhanced}/{len(batch)} CVEs in {batch_duration:.2f} seconds")
        
        # Respect rate limits: wait if needed to comply with rate limit window
        if batch_duration < RATE_LIMIT_WINDOW:
            sleep_time = RATE_LIMIT_WINDOW - batch_duration
            logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
    
    conn.close()
    
    # Final report
    logger.info(f"Enhancement complete:")
    logger.info(f"  - Enhanced: {enhanced_count} CVEs")
    logger.info(f"  - Not found in NVD: {not_found_count} CVEs")
    logger.info(f"  - API Errors: {error_count}")
    logger.info(f"  - Timeouts: {timeout_count}")
    logger.info(f"  - Rate limit hits: {rate_limit_count}")
    
    return enhanced_count

def main():
    """Main function to enhance data quality."""
    logger.info("Starting data quality enhancement process...")
    
    # Get API key securely
    api_key = get_api_key()
    
    # Ask user about processing options
    print("\n=== Processing Options ===")
    print("1. Process all incomplete records")
    print("2. Process incomplete records from recent years (2019+)")
    print("3. Process a limited number of records")
    print("4. Process recent exploited vulnerabilities only")
    
    option = input("\nSelect option (1-4): ").strip()
    
    limit = None
    filter_recent = False
    min_year = 2019
    
    if option == "1":
        # Process all
        pass
    elif option == "2":
        # Recent years
        filter_recent = True
        min_year = int(input("Minimum year to process (e.g. 2019): ") or "2019")
    elif option == "3":
        # Limited number
        try:
            limit = int(input("Maximum number of CVEs to process: ").strip())
        except ValueError:
            logger.warning("Invalid input, processing all records")
    elif option == "4":
        # Recent exploited only
        filter_recent = True
        min_year = 2017
        # We'll use the ordering in identify_incomplete_records to put exploited CVEs first
        limit = int(input("Maximum number of CVEs to process: ") or "500")
    else:
        logger.warning("Invalid option, defaulting to option 2 (recent years)")
        filter_recent = True
    
    # Identify incomplete records
    incomplete_cves = identify_incomplete_records(limit=limit, filter_recent=filter_recent, min_year=min_year)
    
    # Enhance CVE records
    if incomplete_cves:
        enhance_cve_records(incomplete_cves, api_key)
    else:
        logger.info("No incomplete CVEs to process")
    
    logger.info("Data quality enhancement complete")

if __name__ == "__main__":
    main()