# monitor_database.py
import sqlite3
import time
import logging
import sys
import argparse
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database_monitoring.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = 'data/vulnerability_analysis.db'

def get_database_size():
    """Get the size of the database file in MB."""
    try:
        size_bytes = os.path.getsize(DB_PATH)
        size_mb = size_bytes / (1024 * 1024)
        return size_mb
    except Exception as e:
        logger.error(f"Error getting database size: {e}")
        return None

def get_table_stats(conn):
    """Get row counts and column stats for each table in the database."""
    cursor = conn.cursor()
    
    # Get list of tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    # Get counts and column info for each table
    stats = {}
    for table in tables:
        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        
        # Get column info
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Get sample of non-null values for key columns
        column_samples = {}
        for col in columns:
            try:
                cursor.execute(f"SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL LIMIT 1")
                sample = cursor.fetchone()
                if sample:
                    column_samples[col] = sample[0]
            except sqlite3.OperationalError:
                # Skip columns that cause query errors
                pass
        
        stats[table] = {
            'count': count,
            'columns': columns,
            'samples': column_samples
        }
    
    return stats

def get_modified_stats(prev_stats, curr_stats):
    """Compare previous and current stats to identify changes."""
    if not prev_stats:
        return None
    
    changes = {}
    
    # Check each table
    for table in set(list(prev_stats.keys()) + list(curr_stats.keys())):
        # New table
        if table not in prev_stats:
            changes[table] = {'status': 'new', 'count': curr_stats[table]['count']}
            continue
        
        # Removed table
        if table not in curr_stats:
            changes[table] = {'status': 'removed'}
            continue
        
        # Changed row count
        prev_count = prev_stats[table]['count']
        curr_count = curr_stats[table]['count']
        
        if prev_count != curr_count:
            changes[table] = {
                'status': 'modified',
                'count_change': curr_count - prev_count,
                'prev_count': prev_count,
                'curr_count': curr_count
            }
    
    return changes

def monitor_database(interval=5, duration=None):
    """Monitor the database for changes at regular intervals."""
    logger.info(f"Starting database monitoring (interval: {interval}s)")
    print(f"\nMonitoring database: {DB_PATH}")
    print(f"Press Ctrl+C to stop monitoring\n")
    
    start_time = time.time()
    previous_stats = None
    previous_size = None
    
    while True:
        # Check if duration has been reached
        if duration and (time.time() - start_time) > duration:
            logger.info(f"Monitoring duration ({duration}s) reached. Exiting.")
            break
        
        # Connect to database and get stats
        try:
            # Get current time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Get database file size
            current_size = get_database_size()
            size_change = ""
            if previous_size is not None and current_size is not None:
                change = current_size - previous_size
                if abs(change) > 0.01:  # Detect changes larger than 0.01 MB
                    size_change = f" ({'+' if change > 0 else ''}{change:.2f} MB since last check)"
            
            # Connect and get table stats
            conn = sqlite3.connect(DB_PATH)
            current_stats = get_table_stats(conn)
            
            # Identify changes
            changes = get_modified_stats(previous_stats, current_stats)
            
            # Print header with database size
            print(f"\n--- Database Stats at {current_time} ---")
            if current_size is not None:
                print(f"Database size: {current_size:.2f} MB{size_change}")
            
            # Print stats for each table
            if changes:
                print("\nChanges detected:")
                for table, change_info in changes.items():
                    status = change_info['status']
                    
                    if status == 'new':
                        print(f"  ➕ New table: {table} ({change_info['count']} rows)")
                    elif status == 'removed':
                        print(f"  ❌ Removed table: {table}")
                    elif status == 'modified':
                        change = change_info['count_change']
                        print(f"  📝 {table}: {change_info['curr_count']} rows "
                              f"({'+' if change > 0 else ''}{change} since last check)")
            else:
                print("\nNo changes detected in tables")
            
            # Print current table counts
            print("\nCurrent table counts:")
            for table, stats in current_stats.items():
                print(f"  {table}: {stats['count']} rows")
            
            conn.close()
            previous_stats = current_stats
            previous_size = current_size
            
        except Exception as e:
            logger.error(f"Error monitoring database: {e}")
        
        # Wait for next interval
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor SQLite database for changes')
    parser.add_argument('-i', '--interval', type=int, default=5,
                        help='Monitoring interval in seconds (default: 5)')
    parser.add_argument('-d', '--duration', type=int, default=None,
                        help='Total monitoring duration in seconds (default: indefinite)')
    args = parser.parse_args()
    
    try:
        monitor_database(args.interval, args.duration)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")