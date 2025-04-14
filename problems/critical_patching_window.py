# critical_patching_window.py
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy import stats
import os
from datetime import timedelta
import sys

class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, message):
        for f in self.files:
            f.write(message)

    def flush(self):
        for f in self.files:
            f.flush()

# Open a file for logging
log_file = open("critical_patching_window.txt", "w")

# Replace sys.stdout with an instance of Tee that writes to both original sys.stdout and the log file
sys.stdout = Tee(sys.stdout, log_file)

# Now, all print() calls will be written to both the console and log.txt
print("This will appear in the console and be logged.")



# Create output directory
os.makedirs('analysis_results/patching', exist_ok=True)

# Database connection
DB_PATH = '../data/vulnerability_analysis_clean_20250413_203230.db'
conn = sqlite3.connect(DB_PATH)

print("Analyzing critical patching windows between disclosure and exploitation...")

# Query 1: Overall patching window statistics
window_query = """
SELECT 
    v.cve_id,
    v.severity_v3,
    v.cvss_v3_score,
    v.published_date,
    e.date_added as exploitation_date,
    julianday(e.date_added) - julianday(v.published_date) as days_to_exploitation,
    CASE 
        WHEN julianday(e.date_added) - julianday(v.published_date) <= 7 THEN '0-7 days'
        WHEN julianday(e.date_added) - julianday(v.published_date) <= 30 THEN '8-30 days'
        WHEN julianday(e.date_added) - julianday(v.published_date) <= 90 THEN '31-90 days'
        ELSE '90+ days'
    END as window_category
FROM 
    vulnerabilities v
JOIN 
    exploitations e ON v.cve_id = e.cve_id
WHERE 
    v.published_date IS NOT NULL AND 
    e.date_added IS NOT NULL
ORDER BY 
    days_to_exploitation
"""

window_df = pd.read_sql_query(window_query, conn)

# Add negative window category for pre-disclosure exploits
window_df.loc[window_df['days_to_exploitation'] < 0, 'window_category'] = 'Pre-disclosure'

# Convert dates to datetime
window_df['published_date'] = pd.to_datetime(window_df['published_date'])
window_df['exploitation_date'] = pd.to_datetime(window_df['exploitation_date'])


def map_cvss_to_severity(score):
    """Map numeric CVSS v3 scores (1.0–10.0) to a severity category."""
    if pd.isna(score):  
        return 'UNKNOWN'
    elif score >= 8.5:
        return 'CRITICAL'
    elif score >= 6.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score >= 1.0:
        return 'LOW'
    else:
        return 'UNKNOWN'

# Create a derived severity_v3 column in Python
window_df['severity_v3'] = window_df['cvss_v3_score'].apply(map_cvss_to_severity)

# Make it a categorical for nicer plotting/ordering
severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
window_df['severity_v3'] = pd.Categorical(
    window_df['severity_v3'], 
    categories=severity_order, 
    ordered=True
)

# Print basic statistics
print("\nBasic Patching Window Statistics:")
print(f"Total exploited vulnerabilities analyzed: {len(window_df)}")
print(f"Median days to exploitation: {window_df['days_to_exploitation'].median():.1f}")
print(f"Mean days to exploitation: {window_df['days_to_exploitation'].mean():.1f}")
print(f"Minimum days to exploitation: {window_df['days_to_exploitation'].min():.1f}")
print(f"Maximum days to exploitation: {window_df['days_to_exploitation'].max():.1f}")


# Instead of reading from the DB, do an in-memory groupby:
severity_df = window_df.groupby('severity_v3')['days_to_exploitation'].agg(
    count='size',
    avg_days='mean',
    min_days='min',
    max_days='max',
    median_days='median'
).reset_index()

print("\nPatching Windows by Severity:")
print(severity_df)



print("\nPatching Windows by Severity:")
print(severity_df)

# Query 3: Patching window by attack vector
# Modified query without PERCENTILE_CONT
vector_query = """
SELECT 
    attack_vector,
    COUNT(*) as count,
    AVG(days_to_exploitation) as avg_days
FROM 
    view_critical_patching_window
WHERE
    attack_vector IS NOT NULL
GROUP BY 
    attack_vector
"""

vector_df = pd.read_sql_query(vector_query, conn)

# Calculate median in Python
def calculate_vector_median(vector):
    # Get all days_to_exploitation values for this attack vector
    query = f"""
    SELECT days_to_exploitation
    FROM view_critical_patching_window
    WHERE attack_vector = '{vector}'
    """
    days = pd.read_sql_query(query, conn)['days_to_exploitation']
    return days.median() if not days.empty else None

# Add median_days column
vector_df['median_days'] = vector_df['attack_vector'].apply(calculate_vector_median)

print("\nPatching Windows by Attack Vector:")
print(vector_df)

# Query 4: Window category distribution
category_query = """
SELECT 
    CASE 
        WHEN days_to_exploitation < 0 THEN 'Pre-disclosure'
        WHEN days_to_exploitation <= 7 THEN '0-7 days'
        WHEN days_to_exploitation <= 30 THEN '8-30 days'
        WHEN days_to_exploitation <= 90 THEN '31-90 days'
        ELSE '90+ days'
    END as window_category,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM view_critical_patching_window), 2) as percentage
FROM 
    view_critical_patching_window
GROUP BY 
    window_category
ORDER BY 
    CASE 
        WHEN window_category = 'Pre-disclosure' THEN 0
        WHEN window_category = '0-7 days' THEN 1
        WHEN window_category = '8-30 days' THEN 2
        WHEN window_category = '31-90 days' THEN 3
        ELSE 4
    END
"""

category_df = pd.read_sql_query(category_query, conn)

print("\nWindow Category Distribution:")
print(category_df)

# Visualizations

# 1. Histogram of days to exploitation
plt.figure(figsize=(12, 7))
# Filter out extreme values for better visualization
filtered_days = window_df[(window_df['days_to_exploitation'] >= -30) & 
                          (window_df['days_to_exploitation'] <= 365)]

sns.histplot(filtered_days['days_to_exploitation'], bins=30, kde=True)
plt.axvline(x=0, color='red', linestyle='--', label='Disclosure Date')
plt.axvline(x=7, color='orange', linestyle='--', label='7 Days')
plt.axvline(x=30, color='yellow', linestyle='--', label='30 Days')
plt.axvline(x=90, color='green', linestyle='--', label='90 Days')

plt.xlabel('Days Between Disclosure and Exploitation')
plt.ylabel('Number of Vulnerabilities')
plt.title('Distribution of Patching Windows for Exploited Vulnerabilities')
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/patching/patching_window_histogram.png', dpi=300)
plt.close()

# 2. Window category distribution pie chart
plt.figure(figsize=(10, 8))
category_colors = ['darkred', 'orangered', 'orange', 'gold', 'forestgreen']
wedges, texts, autotexts = plt.pie(
    category_df['percentage'], 
    labels=category_df['window_category'],
    autopct='%1.1f%%',
    startangle=90,
    colors=category_colors,
    wedgeprops={'edgecolor': 'white', 'linewidth': 1}
)

for text in autotexts:
    text.set_weight('bold')
    
plt.title('Critical Patching Window Distribution', fontsize=14)
plt.axis('equal')
plt.tight_layout()
plt.savefig('analysis_results/patching/window_category_pie.png', dpi=300)
plt.close()

# 3. Box plot of patching windows by severity
plt.figure(figsize=(12, 7))
# Use the same severity order as before, without None
severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
window_df['severity_v3'] = pd.Categorical(window_df['severity_v3'], categories=severity_order, ordered=True)

# Filter outliers for better visualization
filtered_df = window_df[(window_df['days_to_exploitation'] >= -30) & 
                         (window_df['days_to_exploitation'] <= 365)]

sns.boxplot(x='severity_v3', y='days_to_exploitation', data=filtered_df)
plt.axhline(y=0, color='red', linestyle='--', label='Disclosure Date')
plt.axhline(y=7, color='orange', linestyle='--', label='7 Days')
plt.axhline(y=30, color='yellow', linestyle='--', label='30 Days')
plt.axhline(y=90, color='green', linestyle='--', label='90 Days')

plt.xlabel('Severity Level')
plt.ylabel('Days Between Disclosure and Exploitation')
plt.title('Patching Windows by Vulnerability Severity')
plt.legend()
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/patching/patching_window_by_severity.png', dpi=300)
plt.close()

# 4. Bar chart of median patching windows by attack vector
plt.figure(figsize=(10, 6))
vector_df.sort_values('median_days').plot(
    kind='bar', 
    x='attack_vector', 
    y='median_days', 
    color='steelblue',
    legend=None
)
plt.axhline(y=7, color='orange', linestyle='--', label='7 Days')
plt.axhline(y=30, color='yellow', linestyle='--', label='30 Days')
plt.axhline(y=90, color='green', linestyle='--', label='90 Days')

plt.xlabel('Attack Vector')
plt.ylabel('Median Days to Exploitation')
plt.title('Median Patching Windows by Attack Vector')
plt.legend()
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/patching/median_window_by_vector.png', dpi=300)
plt.close()

# 5. Time series of patching windows over the years
# Modified query without PERCENTILE_CONT
yearly_window_query = """
SELECT 
    strftime('%Y', published_date) as year,
    AVG(days_to_exploitation) as avg_days,
    COUNT(*) as count
FROM 
    view_critical_patching_window
GROUP BY 
    year
ORDER BY 
    year
"""


yearly_window_df = pd.read_sql_query(yearly_window_query, conn)

# Calculate median in Python
def calculate_year_median(year):
    # Get all days_to_exploitation values for this year
    query = f"""
    SELECT days_to_exploitation
    FROM view_critical_patching_window
    WHERE strftime('%Y', published_date) = '{year}'
    """
    days = pd.read_sql_query(query, conn)['days_to_exploitation']
    return days.median() if not days.empty else None

# Add median_days column
yearly_window_df['median_days'] = yearly_window_df['year'].apply(calculate_year_median)
yearly_window_df['year'] = yearly_window_df['year'].astype(int)

# Filter recent years for better visualization (2017-2024)
yearly_window_df = yearly_window_df[(yearly_window_df['year'] >= 2017) & 
                                    (yearly_window_df['year'] <= 2024)]

plt.figure(figsize=(12, 6))
ax1 = plt.subplot(111)
ax2 = ax1.twinx()

# Plot median and average patching windows
ax1.plot(yearly_window_df['year'], yearly_window_df['median_days'], 
         marker='o', color='blue', linewidth=2, label='Median Days')
ax1.plot(yearly_window_df['year'], yearly_window_df['avg_days'], 
         marker='s', color='green', linewidth=2, label='Average Days')
ax1.set_xlabel('Year')
ax1.set_ylabel('Days to Exploitation', color='blue')
ax1.tick_params(axis='y', labelcolor='blue')
ax1.grid(alpha=0.3)

# Plot count of exploited vulnerabilities
ax2.bar(yearly_window_df['year'], yearly_window_df['count'], alpha=0.3, color='gray', label='Count')
ax2.set_ylabel('Number of Vulnerabilities', color='gray')
ax2.tick_params(axis='y', labelcolor='gray')

# Combined legend
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

plt.title('Patching Windows Over Time (2017-2024)')
plt.tight_layout()
plt.savefig('analysis_results/patching/patching_windows_over_time.png', dpi=300)
plt.close()

# Key findings summary
pre_disclosure = category_df[category_df['window_category'] == 'Pre-disclosure']['percentage'].values[0]
critical_window = category_df[category_df['window_category'] == '0-7 days']['percentage'].values[0]
thirty_days = sum(category_df[category_df['window_category'].isin(['Pre-disclosure', '0-7 days', '8-30 days'])]['percentage'])

print("\nKey Findings:")
print(f"- {pre_disclosure:.1f}% of vulnerabilities are exploited before public disclosure")
print(f"- {critical_window:.1f}% of vulnerabilities are exploited within 7 days (critical patching window)")
print(f"- {thirty_days:.1f}% of vulnerabilities are exploited within 30 days of disclosure")
print(f"- Critical vulnerabilities have a median exploitation time of {severity_df[severity_df['severity_v3']=='CRITICAL']['median_days'].values[0]:.1f} days")
print(f"- High severity vulnerabilities have a median exploitation time of {severity_df[severity_df['severity_v3']=='HIGH']['median_days'].values[0]:.1f} days")
print(f"- {vector_df['attack_vector'].iloc[0]} vulnerabilities are exploited fastest, with a median of {vector_df['median_days'].iloc[0]:.1f} days")

# Close connection
conn.close()

print("\nAnalysis complete! Results saved to analysis_results/patching/")