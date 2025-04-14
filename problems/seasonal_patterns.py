# seasonal_patterns.py
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from matplotlib.ticker import PercentFormatter
import os
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
log_file = open("seasonal_patterns.txt", "w")

# Replace sys.stdout with an instance of Tee that writes to both original sys.stdout and the log file
sys.stdout = Tee(sys.stdout, log_file)

# Now, all print() calls will be written to both the console and log.txt
print("This will appear in the console and be logged.")



# Create output directory
os.makedirs('analysis_results/seasonal', exist_ok=True)

# Database connection
DB_PATH = '../data/vulnerability_analysis_clean_20250413_203230.db'
conn = sqlite3.connect(DB_PATH)

print("Analyzing seasonal patterns in vulnerability exploitation...")

# Query 1: Monthly patterns
monthly_query = """
SELECT
    strftime('%m', published_date) AS month,
    COUNT(DISTINCT v.cve_id) AS vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) AS exploitation_rate
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    v.published_date IS NOT NULL
GROUP BY
    month
ORDER BY
    month
"""

monthly_df = pd.read_sql_query(monthly_query, conn)

# Add month names
month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
               'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
monthly_df['month_name'] = monthly_df['month'].astype(int).apply(lambda x: month_names[x-1])

print("\nMonthly Exploitation Patterns:")
print(monthly_df)

# Query 2: Quarter-end analysis
quarter_query = """
SELECT
    is_quarter_end,
    COUNT(DISTINCT v.cve_id) AS vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) AS exploitation_rate
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    v.published_date IS NOT NULL AND
    is_quarter_end IS NOT NULL
GROUP BY
    is_quarter_end
"""

quarter_df = pd.read_sql_query(quarter_query, conn)
quarter_df['period'] = quarter_df['is_quarter_end'].apply(
    lambda x: 'Quarter-End Months' if x == 1 else 'Non-Quarter-End Months')

print("\nQuarter-End Analysis:")
print(quarter_df)

# Query 3: Holiday season analysis
holiday_query = """
SELECT
    is_holiday_season,
    COUNT(DISTINCT v.cve_id) AS vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) AS exploitation_rate
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    v.published_date IS NOT NULL AND
    is_holiday_season IS NOT NULL
GROUP BY
    is_holiday_season
"""

holiday_df = pd.read_sql_query(holiday_query, conn)
holiday_df['period'] = holiday_df['is_holiday_season'].apply(
    lambda x: 'Holiday Season (Nov-Dec)' if x == 1 else 'Non-Holiday Season')

print("\nHoliday Season Analysis:")
print(holiday_df)

# Query 4: Year-over-year monthly patterns
yearly_monthly_query = """
SELECT
    year,
    strftime('%m', published_date) AS month,
    COUNT(DISTINCT v.cve_id) AS vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) AS exploitation_rate
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    v.published_date IS NOT NULL AND
    year BETWEEN 2017 AND 2024
GROUP BY
    year, month
ORDER BY
    year, month
"""

yearly_monthly_df = pd.read_sql_query(yearly_monthly_query, conn)
yearly_monthly_df['month'] = yearly_monthly_df['month'].astype(int)
yearly_monthly_df['month_name'] = yearly_monthly_df['month'].apply(lambda x: month_names[x-1])

# Visualizations

# 1. Monthly vulnerability counts and exploitation rates
fig, ax1 = plt.figure(figsize=(12, 6)), plt.subplot(111)
ax2 = ax1.twinx()

# Plot vulnerability counts as bars
bars = ax1.bar(monthly_df['month_name'], monthly_df['vuln_count'], alpha=0.7, color='steelblue')
ax1.set_xlabel('Month')
ax1.set_ylabel('Number of Vulnerabilities', color='steelblue')
ax1.tick_params(axis='y', labelcolor='steelblue')

# Plot exploitation rate as line
line = ax2.plot(monthly_df['month_name'], monthly_df['exploitation_rate'], 
               marker='o', color='darkred', linewidth=2)
ax2.set_ylabel('Exploitation Rate (%)', color='darkred')
ax2.tick_params(axis='y', labelcolor='darkred')
ax2.yaxis.set_major_formatter(PercentFormatter())

plt.title('Monthly Vulnerability Counts and Exploitation Rates')
plt.grid(axis='y', alpha=0.3)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('analysis_results/seasonal/monthly_patterns.png', dpi=300)
plt.close()

# 2. Quarter-end and Holiday season comparison
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

# Quarter-end comparison
sns.barplot(x='period', y='exploitation_rate', data=quarter_df, ax=ax1)
ax1.set_ylabel('Exploitation Rate (%)')
ax1.set_title('Exploitation Rates for Quarter-End vs. Non-Quarter-End Months')
ax1.yaxis.set_major_formatter(PercentFormatter())
ax1.set_ylim(0, max(quarter_df['exploitation_rate'])*1.2)

# Holiday season comparison
sns.barplot(x='period', y='exploitation_rate', data=holiday_df, ax=ax2)
ax2.set_ylabel('Exploitation Rate (%)')
ax2.set_title('Exploitation Rates for Holiday vs. Non-Holiday Season')
ax2.yaxis.set_major_formatter(PercentFormatter())
ax2.set_ylim(0, max(holiday_df['exploitation_rate'])*1.2)

plt.tight_layout()
plt.savefig('analysis_results/seasonal/seasonal_comparisons.png', dpi=300)
plt.close()

# 3. Heatmap of monthly exploitation rates by year
pivot_df = yearly_monthly_df.pivot(index='year', columns='month_name', values='exploitation_rate')

plt.figure(figsize=(14, 8))
sns.heatmap(pivot_df, annot=True, cmap='YlOrRd', fmt='.2f', 
            linewidths=.5, cbar_kws={'label': 'Exploitation Rate (%)'})
plt.title('Monthly Exploitation Rates by Year (%)')
plt.tight_layout()
plt.savefig('analysis_results/seasonal/yearly_monthly_heatmap.png', dpi=300)
plt.close()

# 4. Year-over-year monthly exploitation rate trends
plt.figure(figsize=(12, 8))
for year in sorted(yearly_monthly_df['year'].unique()):
    year_data = yearly_monthly_df[yearly_monthly_df['year'] == year]
    plt.plot(year_data['month_name'], year_data['exploitation_rate'], 
             marker='o', linewidth=2, label=str(year))

plt.xlabel('Month')
plt.ylabel('Exploitation Rate (%)')
plt.title('Monthly Exploitation Rates by Year')
plt.grid(alpha=0.3)
plt.legend(title='Year')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('analysis_results/seasonal/yearly_monthly_trends.png', dpi=300)
plt.close()

# Key findings summary
highest_month = monthly_df.loc[monthly_df['exploitation_rate'].idxmax()]
lowest_month = monthly_df.loc[monthly_df['exploitation_rate'].idxmin()]

quarter_end_rate = quarter_df[quarter_df['is_quarter_end'] == 1]['exploitation_rate'].values[0]
non_quarter_end_rate = quarter_df[quarter_df['is_quarter_end'] == 0]['exploitation_rate'].values[0]
quarter_diff = quarter_end_rate - non_quarter_end_rate

holiday_rate = holiday_df[holiday_df['is_holiday_season'] == 1]['exploitation_rate'].values[0]
non_holiday_rate = holiday_df[holiday_df['is_holiday_season'] == 0]['exploitation_rate'].values[0]
holiday_diff = holiday_rate - non_holiday_rate

print("\nKey Findings:")
print(f"- Highest exploitation month: {highest_month['month_name']} with {highest_month['exploitation_rate']}% rate")
print(f"- Lowest exploitation month: {lowest_month['month_name']} with {lowest_month['exploitation_rate']}% rate")
print(f"- Quarter-end months have {'higher' if quarter_diff > 0 else 'lower'} exploitation rates " 
      f"by {abs(quarter_diff):.2f} percentage points")
print(f"- Holiday season has {'higher' if holiday_diff > 0 else 'lower'} exploitation rates "
      f"by {abs(holiday_diff):.2f} percentage points")

# Close connection
conn.close()

print("\nAnalysis complete! Results saved to analysis_results/seasonal/")