import numpy as np
import pandas as pd

# Define constants for process log feature engineering
log_transform_cols = ['TRUN', 'TSLPI', 'TSLPU', 'EXC', 'CPU']
scale_cols = ['NICE', 'PRI', 'CPUNR', 'hour', 'day_of_week']
categorical_cols = ['POLI', 'Status', 'State']

def create_temporal_features(df):
    """
    Extract temporal features from timestamp column
    
    Args:
        df (pandas.DataFrame): Input dataframe with 'ts' column
        
    Returns:
        df (pandas.DataFrame): Dataframe with additional time-based features
    """
    df = df.copy()
    
    if 'ts' in df.columns:
        # Convert timestamp to datetime
        df['ts'] = pd.to_datetime(df['ts'], unit='s')
        
        # Extract temporal features
        df['hour'] = df['ts'].dt.hour
        df['day_of_week'] = df['ts'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Drop original timestamp column
        df = df.drop(columns=['ts'])
    
    return df

def apply_log_transform(df):
    """
    Apply log transformation to skewed columns
    
    Args:
        df (pandas.DataFrame): Input dataframe
        
    Returns:
        df (pandas.DataFrame): Dataframe with log-transformed features
    """
    df = df.copy()
    
    for col in log_transform_cols:
        if col in df.columns:
            df[col] = np.log1p(df[col])
    
    return df

def encode_categorical_features(df):
    """
    One-hot encode categorical features with specific handling for known values
    
    Args:
        df (pandas.DataFrame): Input dataframe
        
    Returns:
        df (pandas.DataFrame): Dataframe with one-hot encoded features
    """
    df = df.copy()
    
    # Define expected values for each categorical column
    expected_categories = {
        'POLI': ['0', 'norm'],  # POLI_0, POLI_norm
        'Status': ['0', 'C', 'N', 'NC', 'NE', 'NS'],  # Status_0, Status_C, etc.
        'State': ['E', 'R', 'S', 'T', 'Z']  # State_E, State_R, etc.
    }
    
    # Handle each categorical column separately to ensure all expected values are encoded
    for col in categorical_cols:
        if col in df.columns:
            # For POLI, map 'SCHED_FIFO' to 'norm' and anything else to '0'
            if col == 'POLI':
                # Map scheduling policy values
                df[col] = df[col].map(lambda x: 'norm' if x == 'SCHED_FIFO' else '0')
                
            # For Status, map 'R' to '0' (running), others accordingly
            elif col == 'Status':
                # Map 'R' to '0' (expected value from training)
                df[col] = df[col].map(lambda x: '0' if x == 'R' else x)
                    
            # For State, map 'running' to 'R', others accordingly  
            elif col == 'State':
                # Map 'running' to 'R', etc.
                state_mapping = {
                    'running': 'R',
                    'sleeping': 'S',
                    'zombie': 'Z',
                    'stopped': 'T',
                    'terminated': 'E'
                }
                df[col] = df[col].map(lambda x: state_mapping.get(x, 'R'))
    
    # Create one-hot encoded columns
    for col, expected_vals in expected_categories.items():
        if col in df.columns:
            # Create the expected one-hot columns
            for val in expected_vals:
                col_name = f"{col}_{val}"
                df[col_name] = (df[col] == val).astype(int)
            
            # Remove the original categorical column
            df = df.drop(columns=[col])
    
    return df

def preprocess_features(df):
    """
    Complete preprocessing pipeline for process log features
    
    Args:
        df (pandas.DataFrame): Raw process log dataframe
        
    Returns:
        df (pandas.DataFrame): Preprocessed dataframe ready for model input
    """
    df = df.copy()
    
    # Always set TSLPI and TSLPU to 0 if missing
    if 'TSLPI' not in df.columns:
        df['TSLPI'] = 0.0
    if 'TSLPU' not in df.columns:
        df['TSLPU'] = 0.0
    
    # Drop unnecessary columns
    if 'PID' in df.columns:
        df = df.drop(columns=['PID'])
    
    if 'RTPR' in df.columns:
        df = df.drop(columns=['RTPR'])
    
    if 'CMD' in df.columns:
        df = df.drop(columns=['CMD'])
    
    # Ensure 'type' is dropped to avoid label leakage
    if 'type' in df.columns:
        df = df.drop(columns=['type'])
    
    # Apply transformations
    df = create_temporal_features(df)
    df = apply_log_transform(df)
    df = encode_categorical_features(df)
    
    # Ensure all expected features are present in the correct order
    expected_features = ['TRUN', 'TSLPI', 'TSLPU', 'NICE', 'PRI', 'CPUNR', 'EXC', 'CPU', 
                        'hour', 'day_of_week', 'is_weekend', 
                        'POLI_0', 'POLI_norm', 
                        'Status_0', 'Status_C', 'Status_N', 'Status_NC', 'Status_NE', 'Status_NS',
                        'State_E', 'State_R', 'State_S', 'State_T', 'State_Z']
    
    # Add any missing columns
    for feature in expected_features:
        if feature not in df.columns:
            df[feature] = 0
    
    # Reorder columns to match what the model expects
    df = df[expected_features]
    
    return df
