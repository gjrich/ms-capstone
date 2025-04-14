import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from matplotlib.ticker import PercentFormatter
import os
from scipy import stats
import statistics

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
log_file = open("covid_impact.txt", "w")

# Replace sys.stdout with an instance of Tee that writes to both original sys.stdout and the log file
sys.stdout = Tee(sys.stdout, log_file)

# Now, all print() calls will be written to both the console and log.txt
print("This will appear in the console and be logged.")


# Create output directory
os.makedirs('analysis_results/covid', exist_ok=True)

# Database connection
DB_PATH = '../data/vulnerability_analysis_clean_20250413_203230.db'
conn = sqlite3.connect(DB_PATH)

# Create a custom aggregate for median calculation (used in patching windows)
class Median:
    def __init__(self):
        self.values = []
    def step(self, value):
        if value is not None:
            self.values.append(value)
    def finalize(self):
        return statistics.median(self.values) if self.values else None

conn.create_aggregate("MEDIAN", 1, Median)

print("Analyzing COVID-19 impact on vulnerability exploitation patterns...")

# Define COVID period boundaries
pre_covid_start = '2018-01-01'
pre_covid_end   = '2020-02-29'
during_covid_start = '2020-03-01'
during_covid_end   = '2021-06-30'
post_covid_start   = '2021-07-01'
post_covid_end     = '2023-12-31'

# ---------------------------
# Query 1: Vulnerability counts and exploitation rates by COVID period
# ---------------------------
covid_query = """
SELECT
    CASE 
        WHEN published_date < '2020-03-01' THEN 'Pre-COVID'
        WHEN published_date >= '2020-03-01' AND published_date < '2021-07-01' THEN 'During-COVID'
        WHEN published_date >= '2021-07-01' THEN 'Post-COVID'
    END as covid_period,
    COUNT(DISTINCT v.cve_id) as vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) as exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) as exploitation_rate,
    COUNT(DISTINCT v.cve_id) / 
        (CASE 
            WHEN published_date < '2020-03-01' THEN julianday('2020-03-01') - julianday('2018-01-01')
            WHEN published_date >= '2020-03-01' AND published_date < '2021-07-01' THEN julianday('2021-07-01') - julianday('2020-03-01')
            WHEN published_date >= '2021-07-01' THEN julianday('2023-12-31') - julianday('2021-07-01')
         END / 30.0) as vulns_per_month
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    published_date >= '2018-01-01' AND published_date <= '2023-12-31'
GROUP BY
    covid_period
"""
covid_df = pd.read_sql_query(covid_query, conn)

print("\nCOVID-19 Period Analysis:")
print(covid_df)

# ---------------------------
# Query 2: Monthly vulnerabilities and exploitation rates
# ---------------------------
monthly_query = """
SELECT
    strftime('%Y-%m', published_date) as month,
    COUNT(DISTINCT v.cve_id) as vuln_count,
    SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END) as exploited_count,
    ROUND(SUM(CASE WHEN e.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END) / 
          COUNT(DISTINCT v.cve_id) * 100, 2) as exploitation_rate
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
WHERE
    published_date >= '2018-01-01' AND published_date <= '2023-12-31'
GROUP BY
    month
ORDER BY
    month
"""
monthly_df = pd.read_sql_query(monthly_query, conn)
monthly_df['date'] = pd.to_datetime(monthly_df['month'] + '-01')

# Add COVID period labels based on the month date
monthly_df['covid_period'] = 'Pre-COVID'
monthly_df.loc[monthly_df['date'] >= pd.to_datetime(during_covid_start), 'covid_period'] = 'During-COVID'
monthly_df.loc[monthly_df['date'] >= pd.to_datetime(post_covid_start), 'covid_period'] = 'Post-COVID'

print("\nSample of monthly data:")
print(monthly_df.head())

# ---------------------------
# Query 3: Critical patching window by COVID period
# ---------------------------
patching_query = """
SELECT
    CASE 
        WHEN published_date < '2020-03-01' THEN 'Pre-COVID'
        WHEN published_date >= '2020-03-01' AND published_date < '2021-07-01' THEN 'During-COVID'
        WHEN published_date >= '2021-07-01' THEN 'Post-COVID'
    END as covid_period,
    COUNT(*) as count,
    AVG(days_to_exploitation) as avg_days,
    MEDIAN(days_to_exploitation) as median_days,
    MIN(days_to_exploitation) as min_days,
    MAX(days_to_exploitation) as max_days
FROM
    view_critical_patching_window
WHERE
    published_date >= '2018-01-01' AND published_date <= '2023-12-31'
GROUP BY
    covid_period
"""
patching_df = pd.read_sql_query(patching_query, conn)
patching_df = patching_df[patching_df['min_days'] >= 0]


print("\nPatching Window by COVID Period:")
print(patching_df)

# ---------------------------
# Query 4 (Reworked in Python): Severity distribution by COVID period
# Instead of doing severity mapping inside SQL, we pull raw data and map in Python.
# ---------------------------
severity_data_query = """
SELECT published_date, cvss_v3_score
FROM vulnerabilities
WHERE published_date >= '2018-01-01'
  AND published_date <= '2023-12-31'
  AND cvss_v3_score IS NOT NULL
"""
severity_data_df = pd.read_sql_query(severity_data_query, conn)
severity_data_df['published_date'] = pd.to_datetime(severity_data_df['published_date'])

# Define severity mapping function (mirroring critical_patching_window.py)
def map_cvss_to_severity(score):
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

# Define function to assign COVID period based on published_date
def assign_covid_period(pub_date):
    if pub_date < pd.to_datetime("2020-03-01"):
        return "Pre-COVID"
    elif pub_date < pd.to_datetime("2021-07-01"):
        return "During-COVID"
    else:
        return "Post-COVID"

# Apply the functions
severity_data_df['covid_period'] = severity_data_df['published_date'].apply(assign_covid_period)
severity_data_df['severity_v3'] = severity_data_df['cvss_v3_score'].apply(map_cvss_to_severity)

# Group by COVID period and severity level
grouped = severity_data_df.groupby(['covid_period', 'severity_v3']).size().reset_index(name='count')
total_by_period = severity_data_df.groupby('covid_period').size().reset_index(name='total')
severity_final = pd.merge(grouped, total_by_period, on='covid_period')
severity_final['percentage'] = (severity_final['count'] / severity_final['total']) * 100

print("\nSeverity Distribution by COVID Period (Reworked):")
print(severity_final)

# ---------------------------
# Query 5: Attack vector distribution by COVID period
# ---------------------------
# 5. Attack vector distribution by COVID period (Reworked)
# First, query counts per covid_period and attack_vector only
vector_query = """
SELECT
    CASE 
        WHEN published_date < '2020-03-01' THEN 'Pre-COVID'
        WHEN published_date >= '2020-03-01' AND published_date < '2021-07-01' THEN 'During-COVID'
        WHEN published_date >= '2021-07-01' THEN 'Post-COVID'
    END as covid_period,
    attack_vector,
    COUNT(*) as count
FROM
    vulnerabilities
WHERE
    published_date >= '2018-01-01' AND published_date <= '2023-12-31'
    AND attack_vector IS NOT NULL
GROUP BY
    covid_period, attack_vector
ORDER BY
    covid_period, count DESC
"""
vector_df = pd.read_sql_query(vector_query, conn)


print("\nAttack Vector Distribution by COVID Period:")
print(vector_df)

# ---------------------------
# Statistical Significance Testing
# ---------------------------
pre_covid_rate = covid_df[covid_df['covid_period'] == 'Pre-COVID']['exploitation_rate'].values[0]
during_covid_rate = covid_df[covid_df['covid_period'] == 'During-COVID']['exploitation_rate'].values[0]
post_covid_rate = covid_df[covid_df['covid_period'] == 'Post-COVID']['exploitation_rate'].values[0]

pre_covid_vulns = covid_df[covid_df['covid_period'] == 'Pre-COVID']['vuln_count'].values[0]
during_covid_vulns = covid_df[covid_df['covid_period'] == 'During-COVID']['vuln_count'].values[0]
post_covid_vulns = covid_df[covid_df['covid_period'] == 'Post-COVID']['vuln_count'].values[0]

pre_covid_exploited = covid_df[covid_df['covid_period'] == 'Pre-COVID']['exploited_count'].values[0]
during_covid_exploited = covid_df[covid_df['covid_period'] == 'During-COVID']['exploited_count'].values[0]
post_covid_exploited = covid_df[covid_df['covid_period'] == 'Post-COVID']['exploited_count'].values[0]

# Chi-square test for Pre-COVID vs. During-COVID exploitation rates
observed = np.array([
    [pre_covid_exploited, pre_covid_vulns - pre_covid_exploited],
    [during_covid_exploited, during_covid_vulns - during_covid_exploited],
])
chi2, p_value, _, _ = stats.chi2_contingency(observed)

print("\nStatistical Significance Testing:")
print(f"Chi-square test for Pre-COVID vs During-COVID exploitation rates: Chi2={chi2:.2f}, p-value={p_value:.4f}")
print(f"{'Statistically significant' if p_value < 0.05 else 'Not statistically significant'} at 0.05 level")

# ---------------------------
# Visualizations
# ---------------------------
# 1. Vulnerability counts and exploitation rates by COVID period
plt.figure(figsize=(12, 6))
ax1 = plt.subplot(111)
ax2 = ax1.twinx()

# Vulnerability counts as bars
bars = ax1.bar(covid_df['covid_period'], covid_df['vuln_count'], alpha=0.7, color='steelblue')
ax1.set_xlabel('COVID Period')
ax1.set_ylabel('Number of Vulnerabilities', color='steelblue')
ax1.tick_params(axis='y', labelcolor='steelblue')

# Exploitation rate as a line with points
line = ax2.plot(covid_df['covid_period'], covid_df['exploitation_rate'],
                marker='o', color='darkred', linewidth=2, markersize=10)
ax2.set_ylabel('Exploitation Rate (%)', color='darkred')
ax2.tick_params(axis='y', labelcolor='darkred')
ax2.yaxis.set_major_formatter(PercentFormatter())

# Add value labels
for i, v in enumerate(covid_df['vuln_count']):
    ax1.text(i, v + max(covid_df['vuln_count']) * 0.02, f"{v:,}",
             ha='center', va='bottom', color='steelblue', fontweight='bold')
for i, v in enumerate(covid_df['exploitation_rate']):
    ax2.text(i, v + max(covid_df['exploitation_rate']) * 0.02, f"{v:.2f}%",
             ha='center', va='bottom', color='darkred', fontweight='bold')

plt.title('Vulnerability Counts and Exploitation Rates by COVID-19 Period')
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/covid/covid_period_comparison.png', dpi=300)
plt.close()

# 2. Monthly vulnerability counts and exploitation rates
plt.figure(figsize=(15, 7))
ax1 = plt.subplot(111)
ax2 = ax1.twinx()
colors = {'Pre-COVID': 'steelblue', 'During-COVID': 'firebrick', 'Post-COVID': 'forestgreen'}

for period in monthly_df['covid_period'].unique():
    period_data = monthly_df[monthly_df['covid_period'] == period]
    ax1.bar(period_data['date'], period_data['vuln_count'], alpha=0.7,
            color=colors[period], label=f'{period} Vulnerabilities')

ax1.set_xlabel('Month')
ax1.set_ylabel('Number of Vulnerabilities')
ax1.tick_params(axis='y')

ax2.plot(monthly_df['date'], monthly_df['exploitation_rate'],
         marker='o', color='darkred', linewidth=2, markersize=6, label='Exploitation Rate')
ax2.set_ylabel('Exploitation Rate (%)')
ax2.tick_params(axis='y')
ax2.yaxis.set_major_formatter(PercentFormatter())

plt.axvline(x=pd.to_datetime(during_covid_start), color='black', linestyle='--', label='COVID-19 Start (Mar 2020)')
plt.axvline(x=pd.to_datetime(post_covid_start), color='gray', linestyle='--', label='Post-COVID Start (Jul 2021)')

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

plt.title('Monthly Vulnerability Counts and Exploitation Rates (2019-2023)')
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/covid/monthly_trends_covid.png', dpi=300)
plt.close()

# 3. Patching windows by COVID period
plt.figure(figsize=(12, 6))
bars = plt.bar(patching_df['covid_period'], patching_df['median_days'], color='darkorange')
plt.errorbar(patching_df['covid_period'], patching_df['median_days'],
             yerr=[patching_df['median_days'] - patching_df['min_days'],
                   patching_df['max_days'] - patching_df['median_days']],
             fmt='none', color='black', capsize=10)

plt.xlabel('COVID Period')
plt.ylabel('Median Days Between Disclosure and Exploitation')
plt.title('Critical Patching Windows by COVID-19 Period')
plt.grid(axis='y', alpha=0.3)
for i, v in enumerate(patching_df['median_days']):
    plt.text(i, v + 5, f"{v:.1f} days", ha='center', va='bottom', fontweight='bold')

plt.tight_layout()
plt.savefig('analysis_results/covid/patching_windows_covid.png', dpi=300)
plt.close()

# 4. Severity distribution by COVID period (using Python-calculated data)
# Pivot the aggregated data for a stacked bar chart.
severity_grouped = severity_final.groupby(['covid_period', 'severity_v3'], as_index=False).agg({'count': 'sum', 'percentage': 'mean'})
severity_pivot = severity_grouped.pivot(index='covid_period', columns='severity_v3', values='percentage')

plt.figure(figsize=(12, 6))
severity_pivot.plot(kind='bar', stacked=True, colormap='YlOrRd')
plt.xlabel('COVID Period')
plt.ylabel('Percentage of Vulnerabilities')
plt.title('Severity Distribution by COVID-19 Period')
plt.grid(axis='y', alpha=0.3)
plt.legend(title='Severity Level')
plt.tight_layout()
plt.savefig('analysis_results/covid/severity_distribution_covid.png', dpi=300)
plt.close()

# 5. Attack vector distribution by COVID period
# Focus on top 4 attack vectors

# In case there are duplicate groups, aggregate further (summing counts)
vector_agg = vector_df.groupby(['covid_period', 'attack_vector'], as_index=False).agg({'count': 'sum'})

# Compute percentage for each covid_period by dividing by the total count for that period
vector_agg['percentage'] = vector_agg.groupby('covid_period')['count'] \
                                     .transform(lambda x: round(x * 100.0 / x.sum(), 2))

print("\nAggregated Attack Vector Distribution by COVID Period:")
print(vector_agg)

# Determine the overall top 4 attack vectors (by total count across all periods)
top_vectors = vector_agg.groupby('attack_vector')['count'].sum() \
                        .nlargest(4).index.tolist()

# Filter to only include rows with the top attack vectors
vector_filtered = vector_agg[vector_agg['attack_vector'].isin(top_vectors)]

# Pivot the filtered DataFrame to have one row per covid period and one column per attack vector
vector_pivot = vector_filtered.pivot(index='covid_period', columns='attack_vector', values='percentage')

# Optionally, reindex the rows to ensure ordering by period and columns to follow top_vectors order.
vector_pivot = vector_pivot.reindex(index=['Pre-COVID', 'During-COVID', 'Post-COVID'])
vector_pivot = vector_pivot.reindex(columns=top_vectors)

plt.figure(figsize=(12, 6))
vector_pivot.plot(kind='bar', colormap='Set2')
plt.xlabel('COVID Period')
plt.ylabel('Percentage of Vulnerabilities')
plt.title('Attack Vector Distribution by COVID-19 Period')
plt.grid(axis='y', alpha=0.3)
plt.legend(title='Attack Vector')
plt.tight_layout()
plt.savefig('analysis_results/covid/attack_vector_covid.png', dpi=300)
plt.close()



# ---------------------------
# Key Findings Summary
# ---------------------------
pre_to_during_change = ((during_covid_rate - pre_covid_rate) / pre_covid_rate) * 100
during_to_post_change = ((post_covid_rate - during_covid_rate) / during_covid_rate) * 100
vulns_per_month_change = ((covid_df[covid_df['covid_period'] == 'During-COVID']['vulns_per_month'].values[0] - 
                            covid_df[covid_df['covid_period'] == 'Pre-COVID']['vulns_per_month'].values[0]) / 
                          covid_df[covid_df['covid_period'] == 'Pre-COVID']['vulns_per_month'].values[0]) * 100
patching_window_change = ((patching_df[patching_df['covid_period'] == 'During-COVID']['median_days'].values[0] - 
                            patching_df[patching_df['covid_period'] == 'Pre-COVID']['median_days'].values[0]) / 
                          patching_df[patching_df['covid_period'] == 'Pre-COVID']['median_days'].values[0]) * 100

print("\nKey Findings:")
print(f"- Exploitation rate increased by {pre_to_during_change:.1f}% during COVID compared to pre-COVID period")
print(f"- Exploitation rate changed by {during_to_post_change:.1f}% in post-COVID period compared to during COVID")
print(f"- Monthly vulnerability publications increased by {vulns_per_month_change:.1f}% during the pandemic")
print(f"- Median time to exploitation changed by {patching_window_change:.1f}% during COVID")

if 'NETWORK' in vector_agg['attack_vector'].values:
    network_pre = vector_agg[(vector_agg['covid_period'] == 'Pre-COVID') & 
                              (vector_agg['attack_vector'] == 'NETWORK')]['percentage'].values[0]
    network_during = vector_agg[(vector_agg['covid_period'] == 'During-COVID') & 
                                 (vector_agg['attack_vector'] == 'NETWORK')]['percentage'].values[0]
    network_change = network_during - network_pre
    print(f"- Network-based vulnerabilities {'increased' if network_change > 0 else 'decreased'} by {abs(network_change):.1f} percentage points during COVID")

if p_value < 0.05:
    print(f"- The change in exploitation rates during COVID is statistically significant (p={p_value:.4f})")
else:
    print(f"- The change in exploitation rates during COVID is not statistically significant (p={p_value:.4f})")

# Close the database connection
conn.close()

print("\nAnalysis complete! Results saved to analysis_results/covid/")
