# cve_completeness.py
import sqlite3
import pandas as pd
import os
import matplotlib.pyplot as plt
from datetime import datetime

# Database path
DB_PATH = 'data/vulnerability_analysis.db'

def analyze_cve_completeness():
    """Analyze completeness of CVE records by year and for key research questions."""
    print(f"Analyzing CVE completeness in database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    
    # Define what makes a CVE record incomplete
    incomplete_condition = """
        (description = 'Added from KEV catalog' 
        OR description = 'Added from EPSS data' 
        OR description = 'Added from Exploit-DB data'
        OR description = 'CVE ID not found in NVD database'
        OR (cvss_v3_score IS NULL AND year IS NOT NULL))
    """
    
    # Get total and incomplete CVEs by year
    query = f"""
    SELECT 
        year, 
        COUNT(*) as total_count,
        SUM(CASE WHEN {incomplete_condition} THEN 1 ELSE 0 END) as incomplete_count
    FROM vulnerabilities
    WHERE year IS NOT NULL
    GROUP BY year
    ORDER BY year
    """
    
    result_df = pd.read_sql_query(query, conn)
    result_df['complete_count'] = result_df['total_count'] - result_df['incomplete_count']
    result_df['complete_percentage'] = (result_df['complete_count'] / result_df['total_count'] * 100).round(2)
    
    print("\nCVE Completeness by Year:")
    print(result_df.to_string(index=False))
    
    # Check exploited CVEs specifically
    exploit_query = f"""
    SELECT 
        COUNT(*) as total_exploited,
        SUM(CASE WHEN {incomplete_condition} THEN 1 ELSE 0 END) as incomplete_exploited
    FROM vulnerabilities v
    JOIN exploitations e ON v.cve_id = e.cve_id
    """
    
    exploit_df = pd.read_sql_query(exploit_query, conn)
    exploit_df['complete_exploited'] = exploit_df['total_exploited'] - exploit_df['incomplete_exploited']
    exploit_df['complete_percentage'] = (exploit_df['complete_exploited'] / exploit_df['total_exploited'] * 100).round(2)
    
    print("\nExploited CVEs Completeness:")
    print(exploit_df.to_string(index=False))
    
    # Analyze data relevant to each research question
    questions = [
        ("1. Seasonal Patterns", "view_seasonal_patterns"),
        ("2. Critical Patching Window", "view_critical_patching_window"),
        ("3. Predictive Attributes", "view_exploitation_predictors WHERE is_exploited = 1"),
        ("4. COVID Impact", "view_covid_impact WHERE is_exploited = 1")
    ]
    
    print("\nData Completeness for Research Questions:")
    for question, view in questions:
        query = f"""
        SELECT 
            COUNT(*) as total_records,
            SUM(CASE WHEN {incomplete_condition} THEN 1 ELSE 0 END) as incomplete_records
        FROM vulnerabilities v
        WHERE v.cve_id IN (SELECT cve_id FROM {view})
        """
        
        df = pd.read_sql_query(query, conn)
        df['complete_records'] = df['total_records'] - df['incomplete_records']
        df['complete_percentage'] = (df['complete_records'] / df['total_records'] * 100).round(2)
        
        print(f"\n{question}:")
        print(df.to_string(index=False))
    
    # Create visualization directory
    os.makedirs('analysis_results', exist_ok=True)
    
    # Plot complete vs incomplete by year
    plt.figure(figsize=(15, 8))
    result_df.plot(x='year', y=['complete_count', 'incomplete_count'], kind='bar', stacked=True, 
                   color=['#3498db', '#e74c3c'], figsize=(15, 8))
    plt.title('Complete vs Incomplete CVE Records by Year')
    plt.xlabel('Year')
    plt.ylabel('Number of CVEs')
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.legend(['Complete', 'Incomplete'])
    plt.tight_layout()
    plt.savefig('analysis_results/cve_completeness_by_year.png')
    
    print("\nVisualization saved to 'analysis_results/cve_completeness_by_year.png'")
    
    return result_df, exploit_df, conn, incomplete_condition

def create_clean_database(result_df, exploit_df, conn, incomplete_condition):
    """Check if we have enough complete CVEs and create a clean database."""
    # Calculate average completion percentage for recent years
    recent_years = result_df[result_df['year'] >= 2019]
    avg_recent_completion = recent_years['complete_percentage'].mean()
    
    exploit_completion = exploit_df['complete_percentage'].iloc[0] if len(exploit_df) > 0 else 0
    
    print(f"\nAverage completion for CVEs since 2019: {avg_recent_completion:.2f}%")
    print(f"Completion percentage for exploited CVEs: {exploit_completion:.2f}%")
    
    # Determine if we have enough data
    enough_data = avg_recent_completion >= 50 and exploit_completion >= 70
    
    if enough_data:
        print("\n✅ You have sufficient complete data for your study.")
    else:
        print("\n⚠️ Warning: Some data completeness is below recommended thresholds.")
        print("   This may affect certain analyses but doesn't prevent the study.")
    
    # Ask user if they want to create a clean database
    create_clean = input("\nDo you want to create a clean database with only complete CVEs? (y/n): ")
    
    if create_clean.lower() == 'y':
        # Create new database with timestamp
        clean_db_path = f'data/vulnerability_analysis_clean_{datetime.now().strftime("%Y%m%d")}.db'
        print(f"\nCreating clean database at {clean_db_path}...")
        
        # Create new database
        cursor = conn.cursor()
        
        # Get all table schemas
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        # Create new database connection
        new_conn = sqlite3.connect(clean_db_path)
        new_cursor = new_conn.cursor()
        
        # Copy schema and complete data for each table
        for table_name, table_sql in tables:
            # Create table
            new_cursor.execute(table_sql)
            print(f"Created table: {table_name}")
            
            # For vulnerabilities table, only copy complete records
            if table_name == 'vulnerabilities':
                cursor.execute(f"""
                SELECT * FROM vulnerabilities 
                WHERE NOT {incomplete_condition}
                """)
            else:
                # For other tables, only keep records related to complete vulnerabilities
                cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE cve_id IN (
                    SELECT cve_id FROM vulnerabilities 
                    WHERE NOT {incomplete_condition}
                )
                """)
            
            # Get column count
            columns = len(cursor.description)
            placeholders = ','.join(['?'] * columns)
            
            # Insert data in batches
            batch_size = 10000
            rows = cursor.fetchmany(batch_size)
            count = 0
            
            while rows:
                new_cursor.executemany(f"INSERT INTO {table_name} VALUES ({placeholders})", rows)
                count += len(rows)
                print(f"  Copied {count} records for {table_name}...", end='\r')
                rows = cursor.fetchmany(batch_size)
            
            print(f"  Copied {count} records for {table_name}            ")
        
        # Copy views
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='view'")
        views = cursor.fetchall()
        
        for view_name, view_sql in views:
            try:
                new_cursor.execute(view_sql)
                print(f"Created view: {view_name}")
            except Exception as e:
                print(f"Error creating view {view_name}: {e}")
        
        # Create indexes
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")
        indexes = cursor.fetchall()
        
        for index_sql in indexes:
            try:
                new_cursor.execute(index_sql[0])
            except Exception as e:
                if "already exists" not in str(e):
                    print(f"Error creating index: {e}")
        
        # Commit changes
        new_conn.commit()
        
        # Verify new database
        new_cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        clean_vuln_count = new_cursor.fetchone()[0]
        
        new_cursor.execute("SELECT COUNT(*) FROM exploitations")
        clean_exploit_count = new_cursor.fetchone()[0] if 'exploitations' in [t[0] for t in tables] else 0
        
        print(f"\nClean database created with {clean_vuln_count} complete vulnerabilities")
        print(f"and {clean_exploit_count} exploitation records.")
        print(f"Location: {clean_db_path}")
        
        new_conn.close()
    
    conn.close()
    print("\nAnalysis complete.")

if __name__ == "__main__":
    result_df, exploit_df, conn, incomplete_condition = analyze_cve_completeness()
    create_clean_database(result_df, exploit_df, conn, incomplete_condition)