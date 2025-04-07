# data_standardization.py
import sqlite3
import logging
import sys
from datetime import datetime, timezone
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_standardization.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = 'data/vulnerability_analysis.db'

def standardize_dates():
    """Standardize date formats across all tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Convert Z timezone dates to a standard format
    tables_columns = [
        ('vulnerabilities', 'published_date'),
        ('vulnerabilities', 'last_modified_date'),
        ('exploitations', 'date_added'),
        ('epss_scores', 'score_date'),
        ('public_exploits', 'date_published'),
        ('public_exploits', 'date_added')
    ]
    
    for table, column in tables_columns:
        logger.info(f"Standardizing dates in {table}.{column}")
        
        # First, check if there are any non-standard dates
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} LIKE '%Z'")
        count = cursor.fetchone()[0]
        
        if count > 0:
            # Convert Z timezone dates to YYYY-MM-DD format
            cursor.execute(f'''
            UPDATE {table}
            SET {column} = SUBSTR({column}, 1, 10)
            WHERE {column} LIKE '%Z'
            ''')
            
            logger.info(f"Standardized {cursor.rowcount} dates in {table}.{column}")
    
    conn.commit()
    conn.close()
    logger.info("Date standardization complete")

def create_derived_fields():
    """Create additional derived fields for analysis."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Add month and quarter fields to vulnerabilities for seasonal analysis
    logger.info("Adding month and quarter fields to vulnerabilities")
    
    # Check if columns already exist
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'month' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN month INTEGER")
    
    if 'quarter' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN quarter INTEGER")
    
    if 'is_holiday_season' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN is_holiday_season INTEGER")
    
    if 'is_quarter_end' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN is_quarter_end INTEGER")
    
    if 'is_year_end' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN is_year_end INTEGER")
    
    if 'covid_period' not in columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN covid_period TEXT")
    
    # Update the new columns
    cursor.execute('''
    UPDATE vulnerabilities
    SET month = CAST(strftime('%m', published_date) AS INTEGER),
        quarter = CASE 
            WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 1 AND 3 THEN 1
            WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 4 AND 6 THEN 2
            WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 7 AND 9 THEN 3
            ELSE 4
        END,
        is_holiday_season = CASE 
            WHEN CAST(strftime('%m', published_date) AS INTEGER) IN (11, 12) THEN 1
            ELSE 0
        END,
        is_quarter_end = CASE 
            WHEN CAST(strftime('%m', published_date) AS INTEGER) IN (3, 6, 9, 12) THEN 1
            ELSE 0
        END,
        is_year_end = CASE 
            WHEN CAST(strftime('%m', published_date) AS INTEGER) = 12 THEN 1
            ELSE 0
        END,
        covid_period = CASE 
            WHEN published_date < '2020-03-01' THEN 'Pre-COVID'
            WHEN published_date >= '2020-03-01' AND published_date < '2021-06-01' THEN 'During-COVID'
            WHEN published_date >= '2021-06-01' THEN 'Post-COVID'
            ELSE NULL
        END
    WHERE published_date IS NOT NULL
    ''')
    
    # Calculate average CVSS score by vendor and product
    logger.info("Creating average CVSS score by vendor and product")
    
    # Create or replace view
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_vendor_product_metrics AS
    SELECT 
        ap.vendor,
        ap.product,
        COUNT(DISTINCT v.cve_id) AS vulnerability_count,
        AVG(v.cvss_v3_score) AS avg_cvss_score,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(DISTINCT v.cve_id), 2) AS exploitation_rate
    FROM 
        vulnerabilities v
    JOIN 
        affected_products ap ON v.cve_id = ap.cve_id
    LEFT JOIN 
        exploitations e ON v.cve_id = e.cve_id
    GROUP BY 
        ap.vendor, ap.product
    HAVING 
        COUNT(DISTINCT v.cve_id) >= 5
    ORDER BY 
        exploitation_rate DESC, vulnerability_count DESC
    ''')
    
    # Create view for critical patching window with more details
    logger.info("Creating enhanced critical patching window view")
    
    cursor.execute('''
    CREATE VIEW IF NOT EXISTS view_enhanced_patching_window AS
    SELECT
        v.cve_id,
        v.published_date,
        e.date_added AS exploitation_date,
        julianday(e.date_added) - julianday(v.published_date) AS days_to_exploitation,
        v.severity_v3,
        v.cvss_v3_score,
        v.attack_vector,
        v.attack_complexity,
        v.covid_period,
        CASE 
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 7 THEN '0-7 days'
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 30 THEN '8-30 days'
            WHEN julianday(e.date_added) - julianday(v.published_date) <= 90 THEN '31-90 days'
            ELSE '90+ days'
        END AS exploitation_window,
        GROUP_CONCAT(DISTINCT ap.vendor || ':' || ap.product) AS affected_products,
        MAX(s.epss_score) AS max_epss_score,
        COUNT(DISTINCT pe.id) > 0 AS has_public_exploit
    FROM
        vulnerabilities v
    JOIN
        exploitations e ON v.cve_id = e.cve_id
    LEFT JOIN
        affected_products ap ON v.cve_id = ap.cve_id
    LEFT JOIN
        epss_scores s ON v.cve_id = s.cve_id
    LEFT JOIN
        public_exploits pe ON v.cve_id = pe.cve_id
    WHERE
        v.published_date IS NOT NULL AND
        e.date_added IS NOT NULL
    GROUP BY
        v.cve_id
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Derived fields creation complete")

def main():
    """Main function to standardize data and create derived fields."""
    logger.info("Starting data standardization and derived fields creation...")
    
    # Standardize date formats
    standardize_dates()
    
    # Create derived fields
    create_derived_fields()
    
    logger.info("Data standardization and derived fields creation complete")

if __name__ == "__main__":
    main()