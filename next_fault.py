import pandas as pd
import numpy as np

df = pd.read_csv('only_pfs.csv')

def create_ml_dataset(df, window_size=4):
    features = []
    targets = []
    
    for i in range(window_size, len(df)):
        # Get window of previous faults
        window = df.iloc[i-window_size:i]
        
        # get rel features
        feature_dict = {
            f'latency_t-{j+1}': lat 
            for j, lat in enumerate(reversed(window['fault_latency'].values))
        }
        
        time_gaps = window['timestamp_ns'].diff().values[1:]  # Skip first NaN
        for j, gap in enumerate(reversed(time_gaps)):
            feature_dict[f'time_gap_t-{j+1}'] = gap
            
        page_distances = window['page_id'].diff().values[1:]  # Skip first NaN
        for j, dist in enumerate(reversed(page_distances)):
            feature_dict[f'page_distance_t-{j+1}'] = dist
            
        current_time = window['timestamp_ns'].iloc[-1]
        next_time = df.iloc[i]['timestamp_ns']
        target = next_time - current_time
        
        features.append(feature_dict)
        targets.append(target)
    
    return pd.DataFrame(features), pd.Series(targets)

X, y = create_ml_dataset(df)

X.to_csv('ml_features.csv', index=False)
pd.DataFrame({'time_to_next_fault': y}).to_csv('ml_targets.csv', index=False)

print(f"X shape: {X.shape}")
print(f"Y.shape: {y.shape}")
print("\nFeature columns:")
print(X.columns.tolist())
print("\nFeature statistics:")
print(X.describe())
print("\nTarget statistics:")
print(y.describe())


