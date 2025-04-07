# utils/test_database.py
import sqlite3
import os
import sys
import logging
from config import DB_PATH

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database_testing.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def test_database():
    """Run tests to verify database creation and data loading."""
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found: {DB_PATH}")
        return False
    
    logger.info(f"Testing database at {DB_PATH}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Test table existence and row counts
        tables = [
            'vulnerabilities',
            'cwe',
            'affected_products',
            'exploitations',
            'epss_scores',
            'public_exploits'
        ]
        
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            logger.info(f"Table {table} has {count} rows")
        
        # Test view existence
        views = [
            'view_vulnerability_complete',
            'view_seasonal_patterns',
            'view_critical_patching_window',
            'view_exploitation_predictors',
            'view_covid_impact'
        ]
        
        for view in views:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {view}")
                count = cursor.fetchone()[0]
                logger.info(f"View {view} has {count} rows")
            except sqlite3.Error as e:
                logger.error(f"Error accessing view {view}: {e}")
        
        # Test example queries
        logger.info("Running example queries...")
        
        # Test query 1: Count of vulnerabilities by year and severity
        cursor.execute('''
        SELECT year, severity_v3, COUNT(*) as count
        FROM vulnerabilities
        WHERE year IS NOT NULL AND severity_v3 IS NOT NULL
        GROUP BY year, severity_v3
        ORDER BY year DESC, count DESC
        LIMIT 10
        ''')
        results = cursor.fetchall()
        for row in results:
            logger.info(f"Year: {row[0]}, Severity: {row[1]}, Count: {row[2]}")
        
        # Test query 2: Top 10 most exploited vulnerabilities
        cursor.execute('''
        SELECT 
            v.cve_id, 
            v.cvss_v3_score, 
            v.published_date, 
            e.date_added,
            julianday(e.date_added) - julianday(v.published_date) AS days_to_exploitation
        FROM 
            vulnerabilities v
        JOIN 
            exploitations e ON v.cve_id = e.cve_id
        WHERE 
            v.published_date IS NOT NULL AND
            e.date_added IS NOT NULL
        ORDER BY 
            days_to_exploitation ASC
        LIMIT 10
        ''')
        results = cursor.fetchall()
        for row in results:
            logger.info(f"CVE: {row[0]}, CVSS: {row[1]}, Published: {row[2]}, Exploited: {row[3]}, Days: {row[4]}")
        
        # Test query 3: Exploitation by quarter and year
        cursor.execute('''
        SELECT
            strftime('%Y', v.published_date) AS year,
            CASE 
                WHEN CAST(strftime('%m', v.published_date) AS INTEGER) BETWEEN 1 AND 3 THEN 'Q1'
                WHEN CAST(strftime('%m', v.published_date) AS INTEGER) BETWEEN 4 AND 6 THEN 'Q2'
                WHEN CAST(strftime('%m', v.published_date) AS INTEGER) BETWEEN 7 AND 9 THEN 'Q3'
                ELSE 'Q4' 
            END AS quarter,
            COUNT(v.cve_id) AS vulnerabilities_published,
            SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS vulnerabilities_exploited,
            ROUND(AVG(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100, 2) AS exploitation_rate_percent
        FROM
            vulnerabilities v
        LEFT JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            v.published_date IS NOT NULL
        GROUP BY
            year, quarter
        ORDER BY
            year DESC, quarter
        LIMIT 10
        ''')
        results = cursor.fetchall()
        for row in results:
            logger.info(f"Year: {row[0]}, Quarter: {row[1]}, Vulnerabilities: {row[2]}, Exploited: {row[3]}, Rate: {row[4]}%")
        
        conn.close()
        logger.info("Database tests completed successfully")
        return True
    
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return False
    except Exception as e:
        logger.error(f"General error: {e}")
        return False

if __name__ == "__main__":
    test_database()