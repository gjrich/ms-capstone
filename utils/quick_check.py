
import sqlite3

DB_PATH = 'data/vulnerability_analysis.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

incomplete_condition = """
    (description = 'Added from KEV catalog' 
    OR description = 'Added from EPSS data' 
    OR description = 'Added from Exploit-DB data'
    OR description = 'CVE ID not found in NVD database'
    OR (cvss_v3_score IS NULL AND year IS NOT NULL))
"""

# Research Question 1: Seasonal Patterns
cursor.execute(f"""
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN NOT {incomplete_condition} THEN 1 ELSE 0 END) as complete
FROM vulnerabilities 
WHERE year IS NOT NULL
""")
total, complete = cursor.fetchone()
print(f"1. Seasonal Patterns: {complete}/{total} complete ({complete/total*100:.2f}%)")

# Research Question 2: Critical Patching Window
cursor.execute(f"""
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN NOT {incomplete_condition} THEN 1 ELSE 0 END) as complete
FROM vulnerabilities v
JOIN exploitations e ON v.cve_id = e.cve_id
WHERE v.published_date IS NOT NULL AND e.date_added IS NOT NULL
""")
total, complete = cursor.fetchone()
print(f"2. Critical Patching Window: {complete}/{total} complete ({complete/total*100:.2f}%)")

# Research Question 3: Predictive Attributes
cursor.execute(f"""
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN NOT {incomplete_condition} THEN 1 ELSE 0 END) as complete
FROM vulnerabilities v
WHERE v.cve_id IN (
    SELECT cve_id FROM exploitations
)
""")
total, complete = cursor.fetchone()
print(f"3. Predictive Attributes: {complete}/{total} complete ({complete/total*100:.2f}%)")

# Research Question 4: COVID Impact
cursor.execute(f"""
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN NOT {incomplete_condition} THEN 1 ELSE 0 END) as complete
FROM vulnerabilities v
WHERE v.published_date IS NOT NULL
  AND (v.published_date BETWEEN '2019-01-01' AND '2022-12-31')
""")
total, complete = cursor.fetchone()
print(f"4. COVID Impact: {complete}/{total} complete ({complete/total*100:.2f}%)")

conn.close()