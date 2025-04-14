# clean_database.py
import sqlite3
import os
import time
from datetime import datetime

def clean_database():
    """Create a clean database with only complete CVE records."""
    # Database paths
    original_db = 'data/vulnerability_analysis.db'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_db = f'data/vulnerability_analysis_clean_{timestamp}.db'
    
    print(f"Creating clean database at {clean_db}...")
    
    # Define what makes a CVE record incomplete
    incomplete_condition = """
        (description = 'Added from KEV catalog' 
        OR description = 'Added from EPSS data' 
        OR description = 'Added from Exploit-DB data'
        OR description = 'CVE ID not found in NVD database'
        OR (cvss_v3_score IS NULL AND year IS NOT NULL))
    """
    
    # Connect to databases
    orig_conn = sqlite3.connect(original_db)
    clean_conn = sqlite3.connect(clean_db)
    
    orig_cursor = orig_conn.cursor()
    clean_cursor = clean_conn.cursor()
    
    # Start timing
    start_time = time.time()
    
    # Pre-check: Verify tables exist
    orig_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    existing_tables = [row[0] for row in orig_cursor.fetchall()]
    print(f"Found {len(existing_tables)} tables in original database: {', '.join(existing_tables)}")
    
    # Step 1: Get schema from original database
    print("\nCopying database schema...")
    
    orig_cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = orig_cursor.fetchall()
    
    for table_name, create_sql in tables:
        clean_cursor.execute(create_sql)
        print(f"  Created table {table_name}")
    
    # Step 2: Get complete CVE IDs
    print("\nIdentifying complete CVE records...")
    
    # Get all complete CVE IDs first
    orig_cursor.execute(f"""
    SELECT cve_id FROM vulnerabilities 
    WHERE NOT {incomplete_condition}
    """)
    
    complete_cves = [row[0] for row in orig_cursor.fetchall()]
    print(f"  Found {len(complete_cves)} complete CVE records")
    
    # Step 3: Copy data for each table
    print("\nCopying data to clean database...")
    
    for table_name, _ in tables:
        # Get column names
        orig_cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in orig_cursor.fetchall()]
        columns_str = ', '.join(columns)
        
        # Check if table has cve_id column
        has_cve_id = 'cve_id' in columns
        
        print(f"  Processing table {table_name} ({len(columns)} columns)")
        
        # Direct approach without temporary table
        if table_name == 'vulnerabilities':
            # For vulnerabilities table, copy complete records in batches
            complete_cve_placeholders = ','.join(['?'] * 1000)  # Process in chunks of 1000
            count = 0
            
            for i in range(0, len(complete_cves), 1000):
                chunk = complete_cves[i:i+1000]
                query = f"""
                SELECT {columns_str} FROM vulnerabilities 
                WHERE cve_id IN ({','.join(['?'] * len(chunk))})
                """
                
                orig_cursor.execute(query, chunk)
                batch = orig_cursor.fetchall()
                
                if batch:
                    placeholders = ', '.join(['?'] * len(columns))
                    clean_cursor.executemany(f"INSERT INTO {table_name} VALUES ({placeholders})", batch)
                    count += len(batch)
                    print(f"    {table_name}: Copied {count} rows...", end='\r')
            
            print(f"    {table_name}: Copied {count} rows total         ")
            
        elif has_cve_id:
            # For related tables, copy rows related to complete CVEs in batches
            count = 0
            for i in range(0, len(complete_cves), 1000):
                chunk = complete_cves[i:i+1000]
                query = f"""
                SELECT {columns_str} FROM {table_name}
                WHERE cve_id IN ({','.join(['?'] * len(chunk))})
                """
                
                orig_cursor.execute(query, chunk)
                batch = orig_cursor.fetchall()
                
                if batch:
                    placeholders = ', '.join(['?'] * len(columns))
                    clean_cursor.executemany(f"INSERT INTO {table_name} VALUES ({placeholders})", batch)
                    count += len(batch)
                    print(f"    {table_name}: Copied {count} rows...", end='\r')
            
            print(f"    {table_name}: Copied {count} rows total         ")
            
        else:
            # For tables without cve_id, copy everything
            orig_cursor.execute(f"SELECT {columns_str} FROM {table_name}")
            batch_size = 10000
            batch = orig_cursor.fetchmany(batch_size)
            count = 0
            
            while batch:
                placeholders = ', '.join(['?'] * len(columns))
                clean_cursor.executemany(f"INSERT INTO {table_name} VALUES ({placeholders})", batch)
                count += len(batch)
                print(f"    {table_name}: Copied {count} rows...", end='\r')
                batch = orig_cursor.fetchmany(batch_size)
            
            print(f"    {table_name}: Copied {count} rows total         ")
        
        clean_conn.commit()
    
    # Step 4: Recreate indexes
    print("\nRecreating indexes...")
    
    orig_cursor.execute("""
    SELECT name, sql FROM sqlite_master 
    WHERE type='index' AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
    """)
    
    indexes = orig_cursor.fetchall()
    
    for index_name, index_sql in indexes:
        try:
            clean_cursor.execute(index_sql)
            print(f"  Created index {index_name}")
        except sqlite3.OperationalError as e:
            if "already exists" not in str(e):
                print(f"  Error creating index {index_name}: {e}")
    
    # Step 5: Recreate views
    print("\nRecreating views...")
    
    orig_cursor.execute("""
    SELECT name, sql FROM sqlite_master 
    WHERE type='view' AND name NOT LIKE 'sqlite_%'
    """)
    
    views = orig_cursor.fetchall()
    
    for view_name, view_sql in views:
        try:
            clean_cursor.execute(view_sql)
            print(f"  Created view {view_name}")
        except sqlite3.OperationalError as e:
            print(f"  Error creating view {view_name}: {e}")
    
    # Step 6: Validate the clean database
    print("\nValidating clean database...")
    
    # Validate key tables
    tables_to_check = ['vulnerabilities', 'exploitations', 'epss_scores', 'public_exploits']
    
    for table in tables_to_check:
        clean_cursor.execute(f"SELECT COUNT(*) FROM {table}")
        clean_count = clean_cursor.fetchone()[0]
        
        if table == 'vulnerabilities':
            # Should match our complete CVEs count
            print(f"  {table}: {clean_count} rows (should be {len(complete_cves)})")
        else:
            # Check how many rows we should have
            orig_cursor.execute(f"""
            SELECT COUNT(*) FROM {table} WHERE cve_id IN 
            (SELECT cve_id FROM vulnerabilities WHERE NOT {incomplete_condition})
            """)
            expected_count = orig_cursor.fetchone()[0]
            print(f"  {table}: {clean_count} rows (should be {expected_count})")
    
    # Additional validation for views
    for view_name, _ in views:
        try:
            clean_cursor.execute(f"SELECT COUNT(*) FROM {view_name}")
            view_count = clean_cursor.fetchone()[0]
            print(f"  {view_name}: {view_count} rows")
        except sqlite3.OperationalError as e:
            print(f"  {view_name}: Error - {e}")
    
    # Calculate space savings
    orig_size = os.path.getsize(original_db) / (1024 * 1024)  # Size in MB
    clean_size = os.path.getsize(clean_db) / (1024 * 1024)  # Size in MB
    reduction = (1 - clean_size / orig_size) * 100
    
    print(f"\nDatabase size reduction: {orig_size:.2f}MB → {clean_size:.2f}MB ({reduction:.1f}% smaller)")
    
    # Close connections
    orig_conn.close()
    clean_conn.close()
    
    # Report results
    end_time = time.time()
    print(f"\nDatabase cleaning completed in {end_time - start_time:.2f} seconds")
    print(f"Clean database created at: {clean_db}")
    
    return clean_db

if __name__ == "__main__":
    clean_db_path = clean_database()
    print(f"\nSuccessfully created clean database with only complete CVE records.")
    print(f"You can now use this database for your analysis:")
    print(f"DB_PATH = '{clean_db_path}'")