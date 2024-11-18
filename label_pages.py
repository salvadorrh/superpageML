# label_pages.py
import pandas as pd

# Load the collected metrics
df = pd.read_csv('page_metrics.csv')

# Define thresholds
ACCESS_THRESHOLD = 1000          # Example: >1000 accesses
TLB_MISS_RATE_THRESHOLD = 5.0    # Example: >5%
SPATIAL_LOCALITY_THRESHOLD = 2    # Example: accessed 2 or more neighbors
TEMPORAL_LOCALITY_THRESHOLD = 'High'  # Simplified as Access_Count > ACCESS_THRESHOLD

# Calculate TLB Miss Rate
df['TLB_Miss_Rate'] = (df['TLB_Miss_Count'] / df['Access_Count']) * 100
df['TLB_Miss_Rate'].fillna(0, inplace=True)  # Handle division by zero

# Calculate Spatial Locality
# Assuming 'neighbors_accessed' count is a proxy for spatial locality
df['Spatial_Locality'] = df['neighbors_accessed'].apply(lambda x: 'High' if x >= SPATIAL_LOCALITY_THRESHOLD else ('Medium' if x >= 1 else 'Low'))

# Define a simplified temporal locality based on access frequency
df['Temporal_Locality'] = df['Access_Count'].apply(lambda x: 'High' if x > ACCESS_THRESHOLD else 'Low')

# Define labeling function
def label_promotion(row):
    if (row['Access_Count'] > ACCESS_THRESHOLD and
        row['TLB_Miss_Rate'] > TLB_MISS_RATE_THRESHOLD and
        row['Spatial_Locality'] in ['Medium', 'High'] and
        row['Temporal_Locality'] == 'High'):
        return 1
    else:
        return 0

# Apply labeling
df['Label'] = df.apply(label_promotion, axis=1)

# Save the labeled dataset
df.to_csv('labeled_page_data.csv', index=False)
print("Labeled data saved to labeled_page_data.csv")
