# optimize_database.py
import sqlite3
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database_optimization.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = 'data/vulnerability_analysis.db'

def add_indexes():
    """Add additional indexes to optimize query performance."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Indexes for temporal analysis
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_month ON vulnerabilities(month)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_quarter ON vulnerabilities(quarter)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_holiday_season ON vulnerabilities(is_holiday_season)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_quarter_end ON vulnerabilities(is_quarter_end)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_year_end ON vulnerabilities(is_year_end)")
    
    # Indexes for COVID analysis
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_covid_period ON vulnerabilities(covid_period)")
    
    # Indexes for affected products
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_affected_products_vendor ON affected_products(vendor)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_affected_products_product ON affected_products(product)")
    
    # Compound indexes for common query patterns
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_year_severity ON vulnerabilities(year, severity_v3)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_published_exploited ON vulnerabilities(published_date, cve_id)")
    
    conn.commit()
    conn.close()
    logger.info("Additional indexes created successfully")

def optimize_database():
    """Run SQLite optimizations."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Run VACUUM to defragment the database
    logger.info("Running VACUUM...")
    cursor.execute("VACUUM")
    
    # Run ANALYZE to update statistics
    logger.info("Running ANALYZE...")
    cursor.execute("ANALYZE")
    
    conn.close()
    logger.info("Database optimization complete")

def main():
    """Main function to optimize the database."""
    logger.info("Starting database optimization process...")
    
    # Add additional indexes
    add_indexes()
    
    # Optimize database
    optimize_database()
    
    logger.info("Database optimization complete")

if __name__ == "__main__":
    main()