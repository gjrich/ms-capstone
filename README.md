# Vulnerability Exploitation Analysis

This project analyzes the relationship between published security vulnerabilities and their real-world exploitation, focusing on temporal patterns, patching windows, predictive attributes, and COVID-19 impact.

## Purpose

This research addresses four key questions in cybersecurity:
1. Are there seasonal patterns in vulnerability exploitation?
2. What is the "critical patching window" between vulnerability disclosure and exploitation?
3. What vulnerability attributes are most predictive of subsequent exploitation?
4. How did the COVID-19 pandemic affect vulnerability and breach patterns?

## Architecture

The project follows a modular pipeline architecture:

```
data/                      # Raw data files
├── vulnerability_analysis_clean.db   # SQLite database
utils/                     # Utility scripts
├── config.py              # Configuration settings
├── create_database.py     # Database creation and ETL
├── clean_database.py      # Data cleaning
├── test_database.py       # Database validation
problems/                  # Analysis modules
├── seasonal_patterns.py   # Temporal pattern analysis
├── critical_patching_window.py  # Exploitation timing analysis
├── predictive_attributes.py  # Machine learning prediction
├── covid_impact.py        # Pandemic impact analysis
├── analysis_results/      # Generated visualizations
```

## Methodology

1. **Data Collection**: Integrated data from NVD, CISA KEV, EPSS, and Exploit-DB
2. **Data Processing**: SQLite database with normalized schema for vulnerability attributes
3. **Exploratory Analysis**: Time series decomposition for seasonal patterns
4. **Machine Learning**: Random Forest classifier for exploitation prediction
5. **Visualization**: Statistical analysis of exploitation patterns and trends

## Key Findings

- **Seasonal Patterns**: March shows the highest exploitation rates (0.95%), while June shows the lowest (0.42%)
- **Patching Windows**: 17.1% of exploited vulnerabilities are attacked within 7 days of disclosure
- **Predictive Attributes**: EPSS score, CVSS base score, integrity impact, and public exploit availability are the strongest predictors
- **COVID-19 Impact**: 29.2% increase in exploitation rates during the pandemic period

## Data Sources

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/)
- [Exploit-DB](https://www.exploit-db.com/)

## Usage

1. Clone the repository
2. Install requirements: `pip install -r requirements.txt`
3. Configure data paths in `utils/config.py`
4. Create and populate database: `python utils/create_database.py`
5. Run analysis modules: `python problems/seasonal_patterns.py`

## License

This project is for educational purposes as part of a capstone research project.

## Author

Gabriel J. Richards, Northwest Missouri State University