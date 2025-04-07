# utils/config.py
import os

# Database configuration
DB_PATH = os.path.join('data', 'vulnerability_analysis.db')

# Data paths
NVD_DATA_DIR = os.path.join('data')
EPSS_FILE = os.path.join('data', 'epss_scores-2025-03-30.csv')
KEV_FILE = os.path.join('data', 'known_exploited_vulnerabilities.csv')
EXPLOIT_DB_FILE = os.path.join('data', 'files_exploits.csv')

# Analysis parameters
COVID_START_DATE = '2020-03-01'  # Date to mark beginning of COVID period
COVID_END_DATE = '2021-06-01'    # Date to mark end of COVID period

# CVSS severity thresholds
CVSS_NONE = 0.0
CVSS_LOW = 4.0
CVSS_MEDIUM = 7.0 
CVSS_HIGH = 9.0
CVSS_CRITICAL = 10.0

# Holiday seasons (for seasonal analysis)
HOLIDAY_MONTHS = [11, 12]  # November and December
QUARTER_END_MONTHS = [3, 6, 9, 12]  # March, June, September, December