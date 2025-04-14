# predictive_attributes.py
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.preprocessing import StandardScaler
import os
import warnings
warnings.filterwarnings('ignore')
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
log_file = open("predictive_attributes.txt", "w")

# Replace sys.stdout with an instance of Tee that writes to both original sys.stdout and the log file
sys.stdout = Tee(sys.stdout, log_file)

# Now, all print() calls will be written to both the console and log.txt
print("This will appear in the console and be logged.")



# Create output directory
os.makedirs('analysis_results/predictive', exist_ok=True)

# Database connection
DB_PATH = '../data/vulnerability_analysis_clean_20250413_203230.db'
conn = sqlite3.connect(DB_PATH)

print("Analyzing vulnerability attributes predictive of exploitation...")

# Query to get data for predictive modeling
query = """
SELECT
    v.cve_id,
    v.cvss_v3_score,
    v.attack_vector,
    v.attack_complexity,
    v.privileges_required,
    v.user_interaction,
    v.scope,
    v.confidentiality_impact,
    v.integrity_impact,
    v.availability_impact,
    MAX(s.epss_score) AS max_epss_score,
    CASE WHEN COUNT(p.id) > 0 THEN 1 ELSE 0 END AS has_public_exploit,
    CASE WHEN e.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_exploited
FROM
    vulnerabilities v
LEFT JOIN
    exploitations e ON v.cve_id = e.cve_id
LEFT JOIN
    epss_scores s ON v.cve_id = s.cve_id
LEFT JOIN
    public_exploits p ON v.cve_id = p.cve_id
WHERE
    v.cvss_v3_score IS NOT NULL
GROUP BY
    v.cve_id
"""

df = pd.read_sql_query(query, conn)

# Print basic statistics
print("\nData Overview:")
print(f"Total vulnerabilities: {len(df)}")
print(f"Exploited vulnerabilities: {df['is_exploited'].sum()} ({df['is_exploited'].mean()*100:.2f}%)")
print(f"Vulnerabilities with public exploits: {df['has_public_exploit'].sum()} ({df['has_public_exploit'].mean()*100:.2f}%)")

# Data preparation
# Replace NaN with 'UNKNOWN' for categorical features and 0 for numerical
categorical_features = [
    'attack_vector', 'attack_complexity', 'privileges_required',
    'user_interaction', 'scope', 'confidentiality_impact', 
    'integrity_impact', 'availability_impact'
]

for feature in categorical_features:
    df[feature] = df[feature].fillna('UNKNOWN')

df['max_epss_score'] = df['max_epss_score'].fillna(0)
df['cvss_v3_score'] = df['cvss_v3_score'].fillna(0)

# Create dummy variables for categorical features
df_encoded = pd.get_dummies(df, columns=categorical_features, drop_first=False)

# Prepare features and target
X = df_encoded.drop(['cve_id', 'is_exploited'], axis=1)
y = df_encoded['is_exploited']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# Feature scaling for better model performance
scaler = StandardScaler()
numerical_cols = ['cvss_v3_score', 'max_epss_score']
X_train[numerical_cols] = scaler.fit_transform(X_train[numerical_cols])
X_test[numerical_cols] = scaler.transform(X_test[numerical_cols])

# Train Random Forest model
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\nModel Evaluation:")
print(classification_report(y_test, y_pred))

# Cross-validation
cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1')
print(f"5-fold Cross-validation F1 Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\nTop 10 most important features:")
print(feature_importance.head(10))

# Analysis of each categorical feature's impact on exploitation
print("\nAnalyzing categorical features impact on exploitation:")

for feature in categorical_features:
    feature_values = df[feature].unique()
    feature_stats = []
    
    for value in feature_values:
        if pd.notna(value):
            count = len(df[df[feature] == value])
            exploited = len(df[(df[feature] == value) & (df['is_exploited'] == 1)])
            rate = exploited / count * 100 if count > 0 else 0
            
            feature_stats.append({
                'value': value,
                'count': count,
                'exploited': exploited,
                'exploitation_rate': rate
            })
    
    feature_stats_df = pd.DataFrame(feature_stats)
    if not feature_stats_df.empty:
        feature_stats_df = feature_stats_df.sort_values('exploitation_rate', ascending=False)
        print(f"\n{feature} impact:")
        print(feature_stats_df)

# Visualizations

# 1. Feature importance bar chart (top 15)
plt.figure(figsize=(12, 8))
top_features = feature_importance.head(15).copy()
top_features = top_features.sort_values('importance')  # Sort for horizontal bar chart

plt.barh(top_features['feature'], top_features['importance'], color='darkblue')
plt.xlabel('Importance')
plt.ylabel('Feature')
plt.title('Top 15 Features for Predicting Vulnerability Exploitation')
plt.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/predictive/feature_importance.png', dpi=300)
plt.close()

# 2. ROC curve
plt.figure(figsize=(10, 8))
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)

plt.plot(fpr, tpr, color='blue', lw=2, 
         label=f'ROC curve (area = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/predictive/roc_curve.png', dpi=300)
plt.close()

# 3. Confusion matrix
plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.tight_layout()
plt.savefig('analysis_results/predictive/confusion_matrix.png', dpi=300)
plt.close()

# 4. EPSS score vs exploitation rate
bins = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
df['epss_bin'] = pd.cut(df['max_epss_score'], bins=bins)

epss_stats = df.groupby('epss_bin').agg(
    count=('cve_id', 'count'),
    exploited=('is_exploited', 'sum')
).reset_index()

epss_stats['exploitation_rate'] = epss_stats['exploited'] / epss_stats['count'] * 100

plt.figure(figsize=(12, 6))
bars = plt.bar(epss_stats['epss_bin'].astype(str), epss_stats['exploitation_rate'], color='darkgreen')
plt.xlabel('EPSS Score Range')
plt.ylabel('Exploitation Rate (%)')
plt.title('Relationship Between EPSS Score and Actual Exploitation Rate')
plt.xticks(rotation=45)
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/predictive/epss_vs_exploitation.png', dpi=300)
plt.close()

# 5. Attack vector exploitation rates
attack_vector_stats = []
for vector in df['attack_vector'].unique():
    if pd.notna(vector):
        count = len(df[df['attack_vector'] == vector])
        exploited = len(df[(df['attack_vector'] == vector) & (df['is_exploited'] == 1)])
        rate = exploited / count * 100 if count > 0 else 0
        
        attack_vector_stats.append({
            'attack_vector': vector,
            'count': count,
            'exploited': exploited,
            'exploitation_rate': rate
        })

attack_vector_df = pd.DataFrame(attack_vector_stats)
attack_vector_df = attack_vector_df.sort_values('exploitation_rate', ascending=False)

plt.figure(figsize=(10, 6))
bars = plt.bar(attack_vector_df['attack_vector'], attack_vector_df['exploitation_rate'], color='darkred')
plt.xlabel('Attack Vector')
plt.ylabel('Exploitation Rate (%)')
plt.title('Exploitation Rates by Attack Vector')
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('analysis_results/predictive/attack_vector_rates.png', dpi=300)
plt.close()

# Key findings summary
top_feature = feature_importance['feature'].iloc[0]
top_feature_importance = feature_importance['importance'].iloc[0]

# Get top attack vector by exploitation rate
top_vector = attack_vector_df['attack_vector'].iloc[0]
top_vector_rate = attack_vector_df['exploitation_rate'].iloc[0]

# Calculate EPSS correlation with exploitation
epss_correlation = df['max_epss_score'].corr(df['is_exploited'])

# Find attack complexity impact
if 'attack_complexity' in df.columns:
    ac_low_rate = df[df['attack_complexity'] == 'LOW']['is_exploited'].mean() * 100
    ac_high_rate = df[df['attack_complexity'] == 'HIGH']['is_exploited'].mean() * 100
    ac_diff = ac_low_rate - ac_high_rate
else:
    ac_diff = None

print("\nKey Findings:")
print(f"- The most important feature for predicting exploitation is '{top_feature}' with {top_feature_importance:.4f} importance score")
print(f"- The model achieves {roc_auc:.2f} AUC score, indicating strong predictive power")
print(f"- '{top_vector}' attack vector has the highest exploitation rate at {top_vector_rate:.2f}%")
print(f"- EPSS score has a correlation of {epss_correlation:.4f} with actual exploitation")
if ac_diff is not None:
    print(f"- Low complexity vulnerabilities are exploited {ac_diff:.2f}% more often than high complexity ones")
print(f"- Public exploit availability increases exploitation likelihood by {df.groupby('has_public_exploit')['is_exploited'].mean().iloc[1] / df.groupby('has_public_exploit')['is_exploited'].mean().iloc[0]:.1f}x")

# Close connection
conn.close()

print("\nAnalysis complete! Results saved to analysis_results/predictive/")