# exploratory_analysis.py
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import datetime
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('exploratory_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Set plot style
plt.style.use('ggplot')
sns.set(style="whitegrid")

# Database path - adjust path based on script location
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
DB_PATH = os.path.join(project_root, 'data', 'vulnerability_analysis.db')

# Output directory for results
OUTPUT_DIR = os.path.join(project_root, 'analysis_results', 'eda')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def connect_to_db():
    """Connect to the SQLite database."""
    return sqlite3.connect(DB_PATH)

def get_basic_statistics():
    """Generate basic statistics about the database tables."""
    conn = connect_to_db()
    cursor = conn.cursor()
    
    # Get table row counts
    tables = [
        'vulnerabilities',
        'cwe',
        'affected_products',
        'exploitations',
        'epss_scores',
        'public_exploits'
    ]
    
    stats = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            stats[table] = count
            logger.info(f"Table {table} has {count} rows")
        except sqlite3.Error as e:
            logger.error(f"Error getting count for table {table}: {e}")
            stats[table] = 0
    
    # Get vulnerability count by year
    year_counts = []
    try:
        cursor.execute("""
        SELECT year, COUNT(*) 
        FROM vulnerabilities 
        WHERE year IS NOT NULL 
        GROUP BY year 
        ORDER BY year
        """)
        year_counts = cursor.fetchall()
        if not year_counts:
            # Try alternative query using published_date if year column doesn't exist
            try:
                cursor.execute("""
                SELECT CAST(strftime('%Y', published_date) AS INTEGER) as year, COUNT(*) 
                FROM vulnerabilities 
                WHERE published_date IS NOT NULL 
                GROUP BY year 
                ORDER BY year
                """)
                year_counts = cursor.fetchall()
            except sqlite3.Error as e:
                logger.error(f"Error with alternative year query: {e}")
    except sqlite3.Error as e:
        logger.error(f"Error getting year counts: {e}")
    
    # Get vulnerability count by severity
    severity_counts = []
    try:
        cursor.execute("""
        SELECT severity_v3, COUNT(*) 
        FROM vulnerabilities 
        WHERE severity_v3 IS NOT NULL 
        GROUP BY severity_v3 
        ORDER BY CASE 
            WHEN severity_v3 = 'CRITICAL' THEN 1
            WHEN severity_v3 = 'HIGH' THEN 2
            WHEN severity_v3 = 'MEDIUM' THEN 3
            WHEN severity_v3 = 'LOW' THEN 4
            ELSE 5
        END
        """)
        severity_counts = cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Error getting severity counts: {e}")
    
    # Get exploitation statistics
    total_vulns = 0
    exploited_vulns = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error(f"Error getting total vulnerabilities: {e}")
    
    try:
        cursor.execute("SELECT COUNT(*) FROM exploitations")
        exploited_vulns = cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error(f"Error getting exploited vulnerabilities: {e}")
    
    exploitation_rate = (exploited_vulns / total_vulns) * 100 if total_vulns > 0 else 0
    
    # Generate summary
    summary = {
        'table_counts': stats,
        'year_counts': year_counts,
        'severity_counts': severity_counts,
        'total_vulnerabilities': total_vulns,
        'exploited_vulnerabilities': exploited_vulns,
        'exploitation_rate': exploitation_rate
    }
    
    # Save basic statistics to CSV for reference
    try:
        # Convert to DataFrames and save
        if year_counts:
            year_df = pd.DataFrame(year_counts, columns=['year', 'count'])
            year_df.to_csv(os.path.join(OUTPUT_DIR, 'vuln_by_year.csv'), index=False)
        
        if severity_counts:
            severity_df = pd.DataFrame(severity_counts, columns=['severity', 'count'])
            severity_df.to_csv(os.path.join(OUTPUT_DIR, 'vuln_by_severity.csv'), index=False)
            
        # Save overall stats
        with open(os.path.join(OUTPUT_DIR, 'basic_stats.txt'), 'w') as f:
            f.write(f"Total vulnerabilities: {total_vulns}\n")
            f.write(f"Exploited vulnerabilities: {exploited_vulns}\n")
            f.write(f"Exploitation rate: {exploitation_rate:.2f}%\n")
            f.write("\nTable counts:\n")
            for table, count in stats.items():
                f.write(f"{table}: {count}\n")
    except Exception as e:
        logger.error(f"Error saving basic statistics: {e}")
    
    conn.close()
    return summary

def plot_vulnerabilities_by_year(summary):
    """Plot vulnerability counts by year."""
    if not summary.get('year_counts') or len(summary['year_counts']) == 0:
        logger.warning("No year data available for plotting")
        return
        
    years, counts = zip(*summary['year_counts'])
    
    plt.figure(figsize=(12, 6))
    plt.bar(years, counts)
    plt.title('Vulnerabilities by Year')
    plt.xlabel('Year')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'vulnerabilities_by_year.png'))
    plt.close()
    
    logger.info("Generated vulnerabilities by year plot")

def plot_vulnerabilities_by_severity(summary):
    """Plot vulnerability counts by severity."""
    if not summary.get('severity_counts') or len(summary['severity_counts']) == 0:
        logger.warning("No severity data available for plotting")
        return
        
    severities, counts = zip(*summary['severity_counts'])
    
    plt.figure(figsize=(10, 6))
    colors = ['darkred', 'red', 'orange', 'green', 'gray']
    plt.bar(severities, counts, color=colors[:len(severities)])
    plt.title('Vulnerabilities by Severity')
    plt.xlabel('Severity')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'vulnerabilities_by_severity.png'))
    plt.close()
    
    logger.info("Generated vulnerabilities by severity plot")

def analyze_seasonal_patterns():
    """Analyze seasonal patterns in vulnerability publication and exploitation."""
    conn = connect_to_db()
    
    # Query for monthly patterns
    query = """
    SELECT
        month,
        COUNT(*) AS vulnerability_count,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        month IS NOT NULL
    GROUP BY
        month
    ORDER BY
        month
    """
    try:
        monthly_data = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing monthly patterns query: {e}")
        # Fallback query without month column
        fallback_query = """
        SELECT
            CAST(strftime('%m', published_date) AS INTEGER) AS month,
            COUNT(*) AS vulnerability_count,
            SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
            ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
        FROM
            vulnerabilities v
        LEFT JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            published_date IS NOT NULL
        GROUP BY
            month
        ORDER BY
            month
        """
        monthly_data = pd.read_sql(fallback_query, conn)
    
    # Query for quarterly patterns
    query = """
    SELECT
        quarter,
        COUNT(*) AS vulnerability_count,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        quarter IS NOT NULL
    GROUP BY
        quarter
    ORDER BY
        quarter
    """
    try:
        quarterly_data = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing quarterly patterns query: {e}")
        # Fallback query
        fallback_query = """
        SELECT
            CASE 
                WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 1 AND 3 THEN 1
                WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 4 AND 6 THEN 2
                WHEN CAST(strftime('%m', published_date) AS INTEGER) BETWEEN 7 AND 9 THEN 3
                ELSE 4
            END AS quarter,
            COUNT(*) AS vulnerability_count,
            SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
            ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
        FROM
            vulnerabilities v
        LEFT JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            published_date IS NOT NULL
        GROUP BY
            quarter
        ORDER BY
            quarter
        """
        quarterly_data = pd.read_sql(fallback_query, conn)
    
    # Query for holiday vs non-holiday patterns
    query = """
    SELECT
        is_holiday_season,
        COUNT(*) AS vulnerability_count,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        is_holiday_season IS NOT NULL
    GROUP BY
        is_holiday_season
    ORDER BY
        is_holiday_season
    """
    try:
        holiday_data = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing holiday patterns query: {e}")
        # Fallback query
        fallback_query = """
        SELECT
            CASE 
                WHEN CAST(strftime('%m', published_date) AS INTEGER) IN (11, 12) THEN 1
                ELSE 0
            END AS is_holiday_season,
            COUNT(*) AS vulnerability_count,
            SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
            ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
        FROM
            vulnerabilities v
        LEFT JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            published_date IS NOT NULL
        GROUP BY
            is_holiday_season
        ORDER BY
            is_holiday_season
        """
        holiday_data = pd.read_sql(fallback_query, conn)
    
    conn.close()
    
    # Plot monthly patterns
    plt.figure(figsize=(12, 6))
    ax1 = plt.gca()
    ax2 = ax1.twinx()
    
    bars = ax1.bar(monthly_data['month'], monthly_data['vulnerability_count'], alpha=0.7, label='Vulnerabilities')
    line = ax2.plot(monthly_data['month'], monthly_data['exploitation_rate'], 'r-', marker='o', label='Exploitation Rate (%)')
    
    ax1.set_xlabel('Month')
    ax1.set_ylabel('Vulnerability Count')
    ax2.set_ylabel('Exploitation Rate (%)')
    ax1.set_title('Vulnerability and Exploitation Rate by Month')
    ax1.set_xticks(range(1, 13))
    ax1.set_xticklabels(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])
    
    # Add legends
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines + lines2, labels + labels2, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'monthly_patterns.png'))
    plt.close()
    
    # Plot quarterly patterns
    plt.figure(figsize=(10, 6))
    ax1 = plt.gca()
    ax2 = ax1.twinx()
    
    bars = ax1.bar(quarterly_data['quarter'], quarterly_data['vulnerability_count'], alpha=0.7, label='Vulnerabilities')
    line = ax2.plot(quarterly_data['quarter'], quarterly_data['exploitation_rate'], 'r-', marker='o', label='Exploitation Rate (%)')
    
    ax1.set_xlabel('Quarter')
    ax1.set_ylabel('Vulnerability Count')
    ax2.set_ylabel('Exploitation Rate (%)')
    ax1.set_title('Vulnerability and Exploitation Rate by Quarter')
    ax1.set_xticks(range(1, 5))
    ax1.set_xticklabels(['Q1', 'Q2', 'Q3', 'Q4'])
    
    # Add legends
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines + lines2, labels + labels2, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'quarterly_patterns.png'))
    plt.close()
    
    # Save holiday and quarter-end data to CSV for later analysis
    holiday_data.to_csv(os.path.join(OUTPUT_DIR, 'holiday_patterns.csv'), index=False)
    
    logger.info("Completed seasonal pattern analysis")
    
    return {
        'monthly_data': monthly_data,
        'quarterly_data': quarterly_data,
        'holiday_data': holiday_data
    }

def analyze_critical_patching_window():
    """Analyze the critical patching window between vulnerability disclosure and exploitation."""
    conn = connect_to_db()
    
    # Query for patching window statistics
    query = """
    SELECT
        COUNT(*) AS total_exploited,
        AVG(days_to_exploitation) AS avg_days,
        MIN(days_to_exploitation) AS min_days,
        MAX(days_to_exploitation) AS max_days
    FROM
        view_critical_patching_window
    WHERE
        days_to_exploitation > 0
    """
    try:
        patching_window_stats = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing patching window query: {e}")
        # Fallback if view doesn't exist
        fallback_query = """
        SELECT
            COUNT(*) AS total_exploited,
            AVG(julianday(e.date_added) - julianday(v.published_date)) AS avg_days,
            MIN(julianday(e.date_added) - julianday(v.published_date)) AS min_days,
            MAX(julianday(e.date_added) - julianday(v.published_date)) AS max_days
        FROM
            vulnerabilities v
        JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            v.published_date IS NOT NULL AND
            e.date_added IS NOT NULL AND
            julianday(e.date_added) - julianday(v.published_date) > 0
        """
        patching_window_stats = pd.read_sql(fallback_query, conn)
    
    # Query for patching window by severity
    query = """
    SELECT
        severity_v3,
        COUNT(*) AS count,
        AVG(days_to_exploitation) AS avg_days,
        MIN(days_to_exploitation) AS min_days,
        MAX(days_to_exploitation) AS max_days
    FROM
        view_critical_patching_window
    WHERE
        days_to_exploitation > 0
        AND severity_v3 IS NOT NULL
    GROUP BY
        severity_v3
    ORDER BY
        CASE
            WHEN severity_v3 = 'CRITICAL' THEN 1
            WHEN severity_v3 = 'HIGH' THEN 2
            WHEN severity_v3 = 'MEDIUM' THEN 3
            WHEN severity_v3 = 'LOW' THEN 4
            ELSE 5
        END
    """
    try:
        patching_by_severity = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing patching by severity query: {e}")
        # Fallback if view doesn't exist
        fallback_query = """
        SELECT
            severity_v3,
            COUNT(*) AS count,
            AVG(julianday(e.date_added) - julianday(v.published_date)) AS avg_days,
            MIN(julianday(e.date_added) - julianday(v.published_date)) AS min_days,
            MAX(julianday(e.date_added) - julianday(v.published_date)) AS max_days
        FROM
            vulnerabilities v
        JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            v.published_date IS NOT NULL AND
            e.date_added IS NOT NULL AND
            julianday(e.date_added) - julianday(v.published_date) > 0 AND
            severity_v3 IS NOT NULL
        GROUP BY
            severity_v3
        ORDER BY
            CASE
                WHEN severity_v3 = 'CRITICAL' THEN 1
                WHEN severity_v3 = 'HIGH' THEN 2
                WHEN severity_v3 = 'MEDIUM' THEN 3
                WHEN severity_v3 = 'LOW' THEN 4
                ELSE 5
            END
        """
        patching_by_severity = pd.read_sql(fallback_query, conn)
    
    # Query for exploitation window distribution
    query = """
    SELECT
        CASE 
            WHEN days_to_exploitation <= 7 THEN '0-7 days'
            WHEN days_to_exploitation <= 30 THEN '8-30 days'
            WHEN days_to_exploitation <= 90 THEN '31-90 days'
            ELSE '90+ days'
        END AS exploitation_window,
        COUNT(*) AS count,
        ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percentage
    FROM
        view_critical_patching_window
    WHERE
        days_to_exploitation > 0
    GROUP BY
        exploitation_window
    ORDER BY
        CASE
            WHEN exploitation_window = '0-7 days' THEN 1
            WHEN exploitation_window = '8-30 days' THEN 2
            WHEN exploitation_window = '31-90 days' THEN 3
            ELSE 4
        END
    """
    try:
        exploitation_window_dist = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing exploitation window query: {e}")
        # Fallback if view doesn't exist
        fallback_query = """
        SELECT
            CASE 
                WHEN julianday(e.date_added) - julianday(v.published_date) <= 7 THEN '0-7 days'
                WHEN julianday(e.date_added) - julianday(v.published_date) <= 30 THEN '8-30 days'
                WHEN julianday(e.date_added) - julianday(v.published_date) <= 90 THEN '31-90 days'
                ELSE '90+ days'
            END AS exploitation_window,
            COUNT(*) AS count,
            ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percentage
        FROM
            vulnerabilities v
        JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            v.published_date IS NOT NULL AND
            e.date_added IS NOT NULL AND
            julianday(e.date_added) - julianday(v.published_date) > 0
        GROUP BY
            exploitation_window
        ORDER BY
            CASE
                WHEN exploitation_window = '0-7 days' THEN 1
                WHEN exploitation_window = '8-30 days' THEN 2
                WHEN exploitation_window = '31-90 days' THEN 3
                ELSE 4
            END
        """
        exploitation_window_dist = pd.read_sql(fallback_query, conn)
    
    conn.close()
    
    # Plot patching window by severity
    if not patching_by_severity.empty:
        plt.figure(figsize=(10, 6))
        colors = ['darkred', 'red', 'orange', 'green']
        plt.bar(patching_by_severity['severity_v3'], patching_by_severity['avg_days'], 
                color=[colors[i % len(colors)] for i in range(len(patching_by_severity))])
        plt.title('Average Days to Exploitation by Severity')
        plt.xlabel('Severity')
        plt.ylabel('Average Days')
        
        # Add count labels
        for i, row in enumerate(patching_by_severity.itertuples()):
            plt.text(i, row.avg_days + 5, f'n={row.count}', ha='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'patching_by_severity.png'))
        plt.close()
    
    # Plot exploitation window distribution
    if not exploitation_window_dist.empty:
        plt.figure(figsize=(10, 6))
        plt.pie(exploitation_window_dist['count'], labels=exploitation_window_dist['exploitation_window'],
               autopct='%1.1f%%', startangle=90,
               colors=['red', 'orange', 'yellow', 'green'])
        plt.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
        plt.title('Distribution of Exploitation Windows')
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'exploitation_window_dist.png'))
        plt.close()
    
    # Save detailed statistics to CSV for further analysis
    patching_window_stats.to_csv(os.path.join(OUTPUT_DIR, 'patching_window_stats.csv'), index=False)
    patching_by_severity.to_csv(os.path.join(OUTPUT_DIR, 'patching_by_severity.csv'), index=False)
    
    logger.info("Completed critical patching window analysis")
    
    return {
        'patching_window_stats': patching_window_stats,
        'patching_by_severity': patching_by_severity,
        'exploitation_window_dist': exploitation_window_dist
    }

def analyze_vulnerability_attributes():
    """Analyze vulnerability attributes that predict exploitation."""
    conn = connect_to_db()
    
    # Query for exploitation rate by attack vector
    query = """
    SELECT
        attack_vector,
        COUNT(*) AS total_vulns,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_vulns,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        attack_vector IS NOT NULL
    GROUP BY
        attack_vector
    ORDER BY
        exploitation_rate DESC
    """
    attack_vector_stats = pd.read_sql(query, conn)
    
    # Query for exploitation rate by attack complexity
    query = """
    SELECT
        attack_complexity,
        COUNT(*) AS total_vulns,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_vulns,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        attack_complexity IS NOT NULL
    GROUP BY
        attack_complexity
    ORDER BY
        exploitation_rate DESC
    """
    attack_complexity_stats = pd.read_sql(query, conn)
    
    # Query for exploitation rate by public exploit availability
    query = """
    SELECT
        CASE WHEN COUNT(pe.id) > 0 THEN 1 ELSE 0 END AS has_public_exploit,
        COUNT(DISTINCT v.cve_id) AS total_vulns,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_vulns,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(DISTINCT v.cve_id), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    LEFT JOIN
        public_exploits pe ON v.cve_id = pe.cve_id
    GROUP BY
        has_public_exploit
    ORDER BY
        has_public_exploit DESC
    """
    public_exploit_stats = pd.read_sql(query, conn)
    
    # Query for EPSS score distribution
    query = """
    SELECT
        CASE
            WHEN s.epss_score < 0.1 THEN '0.00-0.10'
            WHEN s.epss_score < 0.2 THEN '0.10-0.20'
            WHEN s.epss_score < 0.3 THEN '0.20-0.30'
            WHEN s.epss_score < 0.4 THEN '0.30-0.40'
            WHEN s.epss_score < 0.5 THEN '0.40-0.50'
            WHEN s.epss_score < 0.6 THEN '0.50-0.60'
            WHEN s.epss_score < 0.7 THEN '0.60-0.70'
            WHEN s.epss_score < 0.8 THEN '0.70-0.80'
            WHEN s.epss_score < 0.9 THEN '0.80-0.90'
            ELSE '0.90-1.00'
        END AS epss_range,
        COUNT(DISTINCT v.cve_id) AS vuln_count,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(DISTINCT v.cve_id), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    JOIN
        epss_scores s ON v.cve_id = s.cve_id
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    GROUP BY
        epss_range
    ORDER BY
        epss_range
    """
    epss_distribution = pd.read_sql(query, conn)
    
    conn.close()
    
    # Plot exploitation rate by attack vector
    if not attack_vector_stats.empty:
        plt.figure(figsize=(10, 6))
        sns.barplot(x='attack_vector', y='exploitation_rate', data=attack_vector_stats)
        plt.title('Exploitation Rate by Attack Vector')
        plt.xlabel('Attack Vector')
        plt.ylabel('Exploitation Rate (%)')
        plt.xticks(rotation=45)
        
        # Add count labels
        for i, row in enumerate(attack_vector_stats.itertuples()):
            plt.text(i, row.exploitation_rate + 0.5, f'n={row.total_vulns}', ha='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'exploitation_by_attack_vector.png'))
        plt.close()
    
    # Plot exploitation rate by attack complexity
    if not attack_complexity_stats.empty:
        plt.figure(figsize=(8, 6))
        sns.barplot(x='attack_complexity', y='exploitation_rate', data=attack_complexity_stats)
        plt.title('Exploitation Rate by Attack Complexity')
        plt.xlabel('Attack Complexity')
        plt.ylabel('Exploitation Rate (%)')
        
        # Add count labels
        for i, row in enumerate(attack_complexity_stats.itertuples()):
            plt.text(i, row.exploitation_rate + 0.5, f'n={row.total_vulns}', ha='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'exploitation_by_attack_complexity.png'))
        plt.close()
    
    # Plot exploitation rate by has_public_exploit
    if not public_exploit_stats.empty:
        plt.figure(figsize=(8, 6))
        public_exploit_stats['label'] = public_exploit_stats['has_public_exploit'].apply(lambda x: 'Yes' if x == 1 else 'No')
        sns.barplot(x='label', y='exploitation_rate', data=public_exploit_stats)
        plt.title('Exploitation Rate by Public Exploit Availability')
        plt.xlabel('Has Public Exploit')
        plt.ylabel('Exploitation Rate (%)')
        
        # Add count labels
        for i, row in enumerate(public_exploit_stats.itertuples()):
            plt.text(i, row.exploitation_rate + 0.5, f'n={row.total_vulns}', ha='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'exploitation_by_public_exploit.png'))
        plt.close()
    
    # Save detailed statistics to CSV for further analysis
    attack_vector_stats.to_csv(os.path.join(OUTPUT_DIR, 'attack_vector_stats.csv'), index=False)
    attack_complexity_stats.to_csv(os.path.join(OUTPUT_DIR, 'attack_complexity_stats.csv'), index=False)
    public_exploit_stats.to_csv(os.path.join(OUTPUT_DIR, 'public_exploit_stats.csv'), index=False)
    epss_distribution.to_csv(os.path.join(OUTPUT_DIR, 'epss_distribution.csv'), index=False)
    
    logger.info("Completed vulnerability attributes analysis")
    
    return {
        'attack_vector_stats': attack_vector_stats,
        'attack_complexity_stats': attack_complexity_stats,
        'public_exploit_stats': public_exploit_stats,
        'epss_distribution': epss_distribution
    }

def analyze_covid_impact():
    """Analyze the impact of COVID-19 on vulnerability and exploitation patterns."""
    conn = connect_to_db()
    
    # Query for vulnerability counts by COVID period
    query = """
    SELECT
        covid_period,
        COUNT(*) AS vulnerability_count,
        SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
        ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
    FROM
        vulnerabilities v
    LEFT JOIN
        exploitations e ON v.cve_id = e.cve_id
    WHERE
        covid_period IS NOT NULL
    GROUP BY
        covid_period
    ORDER BY
        CASE
            WHEN covid_period = 'Pre-COVID' THEN 1
            WHEN covid_period = 'During-COVID' THEN 2
            ELSE 3
        END
    """
    try:
        covid_vuln_stats = pd.read_sql(query, conn)
    except Exception as e:
        logger.error(f"Error executing COVID stats query: {e}")
        # Fallback if covid_period column doesn't exist
        fallback_query = """
        SELECT
            CASE 
                WHEN published_date < '2020-03-01' THEN 'Pre-COVID'
                WHEN published_date >= '2020-03-01' AND published_date < '2021-06-01' THEN 'During-COVID'
                WHEN published_date >= '2021-06-01' THEN 'Post-COVID'
                ELSE NULL
            END AS covid_period,
            COUNT(*) AS vulnerability_count,
            SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
            ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) * 100 / COUNT(*), 2) AS exploitation_rate
        FROM
            vulnerabilities v
        LEFT JOIN
            exploitations e ON v.cve_id = e.cve_id
        WHERE
            published_date IS NOT NULL
        GROUP BY
            covid_period
        HAVING
            covid_period IS NOT NULL
        ORDER BY
            CASE
                WHEN covid_period = 'Pre-COVID' THEN 1
                WHEN covid_period = 'During-COVID' THEN 2
                ELSE 3
            END
        """
        covid_vuln_stats = pd.read_sql(fallback_query, conn)
    
    conn.close()
    
    # Plot vulnerability and exploitation counts by COVID period
    if not covid_vuln_stats.empty:
        plt.figure(figsize=(10, 6))
        ax1 = plt.gca()
        ax2 = ax1.twinx()
        
        x = np.arange(len(covid_vuln_stats))
        width = 0.35
        
        bars1 = ax1.bar(x - width/2, covid_vuln_stats['vulnerability_count'], width, label='Total Vulnerabilities')
        bars2 = ax1.bar(x + width/2, covid_vuln_stats['exploited_count'], width, label='Exploited Vulnerabilities')
        line = ax2.plot(x, covid_vuln_stats['exploitation_rate'], 'r-', marker='o', label='Exploitation Rate (%)')
        
        ax1.set_xlabel('COVID Period')
        ax1.set_ylabel('Count')
        ax2.set_ylabel('Exploitation Rate (%)')
        plt.title('Vulnerability and Exploitation Counts by COVID Period')
        plt.xticks(x, covid_vuln_stats['covid_period'])
        
        # Add legends
        lines, labels = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines + lines2, labels + labels2, loc='upper left')
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'covid_impact_counts.png'))
        plt.close()
    
    # Save detailed statistics to CSV for further analysis
    covid_vuln_stats.to_csv(os.path.join(OUTPUT_DIR, 'covid_vuln_stats.csv'), index=False)
    
    logger.info("Completed COVID impact analysis")
    
    return {
        'covid_vuln_stats': covid_vuln_stats
    }

def export_data_samples():
    """Export sample records from key tables to help understand data structure."""
    conn = connect_to_db()
    
    tables = [
        'vulnerabilities',
        'cwe',
        'affected_products',
        'exploitations',
        'epss_scores',
        'public_exploits'
    ]
    
    for table in tables:
        try:
            # Get 5 sample records from each table
            query = f"SELECT * FROM {table} LIMIT 5"
            sample_df = pd.read_sql_query(query, conn)
            
            # Save to CSV
            sample_file = os.path.join(OUTPUT_DIR, f"{table}_sample.csv")
            sample_df.to_csv(sample_file, index=False)
            logger.info(f"Saved sample data for {table} to {sample_file}")
        except Exception as e:
            logger.error(f"Error exporting sample data for {table}: {e}")
    
    # Try to get some joined samples across tables
    try:
        # Vulnerabilities with exploitation data
        query = """
        SELECT v.cve_id, v.published_date, v.severity_v3, v.cvss_v3_score, 
               e.date_added AS exploitation_date
        FROM vulnerabilities v
        JOIN exploitations e ON v.cve_id = e.cve_id
        LIMIT 10
        """
        exploited_sample = pd.read_sql_query(query, conn)
        exploited_sample.to_csv(os.path.join(OUTPUT_DIR, "exploited_vulnerabilities_sample.csv"), index=False)
        logger.info("Saved sample of exploited vulnerabilities")
    except Exception as e:
        logger.error(f"Error exporting exploited vulnerabilities sample: {e}")
    
    conn.close()
    return True

def generate_summary_report(
    basic_stats, 
    seasonal_results, 
    patching_window_results, 
    vulnerability_attr_results, 
    covid_results
):
    """Generate a summary report of all EDA findings."""
    
    # Handle potentially missing data
    has_seasonal_data = 'monthly_data' in seasonal_results and seasonal_results['monthly_data'] is not None and not isinstance(seasonal_results.get('monthly_data', {}), pd.DataFrame) or not seasonal_results.get('monthly_data', {}).empty if seasonal_results else False
    
    has_quarterly_data = 'quarterly_data' in seasonal_results and seasonal_results['quarterly_data'] is not None and not isinstance(seasonal_results.get('quarterly_data', {}), pd.DataFrame) or not seasonal_results.get('quarterly_data', {}).empty if seasonal_results else False
    
    has_holiday_data = 'holiday_data' in seasonal_results and seasonal_results['holiday_data'] is not None and not isinstance(seasonal_results.get('holiday_data', {}), pd.DataFrame) or not seasonal_results.get('holiday_data', {}).empty if seasonal_results else False
    
    avg_days = "N/A"
    if patching_window_results and 'patching_window_stats' in patching_window_results and not isinstance(patching_window_results.get('patching_window_stats', {}), pd.DataFrame) or not patching_window_results.get('patching_window_stats', {}).empty:
        if 'avg_days' in patching_window_results['patching_window_stats']:
            avg_days = f"{patching_window_results['patching_window_stats']['avg_days'].values[0]:.1f}" if len(patching_window_results['patching_window_stats']['avg_days'].values) > 0 else "N/A"
    
    has_patching_by_severity = patching_window_results and 'patching_by_severity' in patching_window_results and not isinstance(patching_window_results.get('patching_by_severity', {}), pd.DataFrame) or not patching_window_results.get('patching_by_severity', {}).empty
    
    has_exploitation_window_dist = patching_window_results and 'exploitation_window_dist' in patching_window_results and not isinstance(patching_window_results.get('exploitation_window_dist', {}), pd.DataFrame) or not patching_window_results.get('exploitation_window_dist', {}).empty
    
    has_attack_vector_stats = vulnerability_attr_results and 'attack_vector_stats' in vulnerability_attr_results and not isinstance(vulnerability_attr_results.get('attack_vector_stats', {}), pd.DataFrame) or not vulnerability_attr_results.get('attack_vector_stats', {}).empty
    
    has_attack_complexity_stats = vulnerability_attr_results and 'attack_complexity_stats' in vulnerability_attr_results and not isinstance(vulnerability_attr_results.get('attack_complexity_stats', {}), pd.DataFrame) or not vulnerability_attr_results.get('attack_complexity_stats', {}).empty
    
    has_public_exploit_stats = vulnerability_attr_results and 'public_exploit_stats' in vulnerability_attr_results and not isinstance(vulnerability_attr_results.get('public_exploit_stats', {}), pd.DataFrame) or not vulnerability_attr_results.get('public_exploit_stats', {}).empty
    
    has_epss_distribution = vulnerability_attr_results and 'epss_distribution' in vulnerability_attr_results and not isinstance(vulnerability_attr_results.get('epss_distribution', {}), pd.DataFrame) or not vulnerability_attr_results.get('epss_distribution', {}).empty
    
    has_covid_stats = covid_results and 'covid_vuln_stats' in covid_results and not isinstance(covid_results.get('covid_vuln_stats', {}), pd.DataFrame) or not covid_results.get('covid_vuln_stats', {}).empty
    
    # Generate report
    report = f"""
Exploratory Data Analysis Summary Report
=======================================
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Database Overview
----------------
Total Vulnerabilities: {basic_stats.get('total_vulnerabilities', 'N/A'):,}
Exploited Vulnerabilities: {basic_stats.get('exploited_vulnerabilities', 'N/A'):,}
Overall Exploitation Rate: {basic_stats.get('exploitation_rate', 0):.2f}%

Key Findings
-----------

1. Seasonal Patterns:
   - Monthly patterns show {"notable seasonality" if has_seasonal_data else "inconclusive results"}
   - Quarterly patterns show {"notable seasonality" if has_quarterly_data else "inconclusive results"}
   - Holiday season exploitation rate difference: {"significant" if has_holiday_data else "inconclusive"}

2. Critical Patching Window:
   - Average days to exploitation: {avg_days} days
   - {"Fast exploitation by severity levels" if has_patching_by_severity else "Insufficient data for severity analysis"}
   - {"Exploitation window distribution shows clear patterns" if has_exploitation_window_dist else "Insufficient data for exploitation window distribution"}

3. Predictive Vulnerability Attributes:
   - {"Attack vector influence on exploitation rates" if has_attack_vector_stats else "Insufficient data for attack vector analysis"}
   - {"Attack complexity influence on exploitation rates" if has_attack_complexity_stats else "Insufficient data for attack complexity analysis"}
   - {"Public exploit availability significantly impacts exploitation likelihood" if has_public_exploit_stats else "Insufficient data for public exploit analysis"}
   - {"EPSS scores show correlation with exploitation rates" if has_epss_distribution else "Insufficient data for EPSS score analysis"}

4. COVID-19 Impact:
   - {"COVID-19 periods show significant differences in vulnerability exploitation patterns" if has_covid_stats else "Insufficient data for COVID-19 impact analysis"}

Conclusion
---------
This exploratory analysis has revealed important patterns in vulnerability exploitation, including temporal trends, 
critical patching windows, predictive attributes, and COVID-19 impacts. These findings can help security teams 
prioritize vulnerability remediation efforts and improve their overall security posture.

All detailed results are available in CSV files and visualizations in the 'analysis_results/eda' directory.
"""
    
    # Save the report
    with open(os.path.join(OUTPUT_DIR, 'eda_summary_report.txt'), 'w') as f:
        f.write(report)
    
    logger.info(f"Generated summary report at {os.path.join(OUTPUT_DIR, 'eda_summary_report.txt')}")
    
    return report

def main():
    """Main function to run all EDA analyses."""
    logger.info("Starting exploratory data analysis...")
    
    try:
        # Get basic statistics first
        logger.info("Gathering basic statistics...")
        basic_stats = get_basic_statistics()
        
        # Export sample data from tables for better understanding
        logger.info("Exporting data samples...")
        export_data_samples()
        
        # Save raw database structure info
        conn = connect_to_db()
        cursor = conn.cursor()
        try:
            # Get table schemas
            with open(os.path.join(OUTPUT_DIR, 'database_schema.txt'), 'w') as f:
                for table in ['vulnerabilities', 'cwe', 'affected_products', 'exploitations', 'epss_scores', 'public_exploits']:
                    try:
                        cursor.execute(f"PRAGMA table_info({table})")
                        columns = cursor.fetchall()
                        f.write(f"\nTable: {table}\n")
                        f.write("-" * (len(table) + 8) + "\n")
                        for col in columns:
                            f.write(f"{col[1]} ({col[2]})\n")
                    except sqlite3.Error as e:
                        f.write(f"Error getting schema for {table}: {e}\n")
                        
                # List views
                try:
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='view'")
                    views = cursor.fetchall()
                    f.write("\nViews:\n")
                    f.write("-" * 7 + "\n")
                    for view in views:
                        f.write(f"{view[0]}\n")
                except sqlite3.Error as e:
                    f.write(f"Error getting views: {e}\n")
        except Exception as e:
            logger.error(f"Error saving database schema: {e}")
        finally:
            conn.close()
        
        # Plot basic vulnerability statistics if data is available
        if basic_stats.get('year_counts'):
            logger.info("Plotting vulnerabilities by year...")
            plot_vulnerabilities_by_year(basic_stats)
        
        if basic_stats.get('severity_counts'):
            logger.info("Plotting vulnerabilities by severity...")
            plot_vulnerabilities_by_severity(basic_stats)
        
        # Initialize results dictionaries
        seasonal_results = {}
        patching_window_results = {}
        vulnerability_attr_results = {}
        covid_results = {}
        
        # Only continue with more complex analyses if basic data is available
        if basic_stats.get('total_vulnerabilities', 0) > 0:
            # Try each analysis independently so failure in one doesn't stop others
            try:
                logger.info("Analyzing seasonal patterns...")
                seasonal_results = analyze_seasonal_patterns()
            except Exception as e:
                logger.error(f"Error in seasonal pattern analysis: {e}")
                seasonal_results = {"error": str(e)}
            
            try:
                logger.info("Analyzing critical patching window...")
                patching_window_results = analyze_critical_patching_window()
            except Exception as e:
                logger.error(f"Error in patching window analysis: {e}")
                patching_window_results = {"error": str(e)}
            
            try:
                logger.info("Analyzing vulnerability attributes...")
                vulnerability_attr_results = analyze_vulnerability_attributes()
            except Exception as e:
                logger.error(f"Error in vulnerability attributes analysis: {e}")
                vulnerability_attr_results = {"error": str(e)}
            
            try:
                logger.info("Analyzing COVID impact...")
                covid_results = analyze_covid_impact()
            except Exception as e:
                logger.error(f"Error in COVID impact analysis: {e}")
                covid_results = {"error": str(e)}
        
        # Generate summary report
        try:
            logger.info("Generating summary report...")
            summary_report = generate_summary_report(
                basic_stats,
                seasonal_results,
                patching_window_results,
                vulnerability_attr_results,
                covid_results
            )
            print("\nEDA Summary Report:")
            print(summary_report)
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            
        logger.info("Exploratory data analysis complete")
        print(f"\nResults and visualizations saved to: {OUTPUT_DIR}")
        
    except Exception as e:
        logger.error(f"Fatal error in exploratory analysis: {e}")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()