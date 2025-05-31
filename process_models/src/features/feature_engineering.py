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
    One-hot encode categorical features
    
    Args:
        df (pandas.DataFrame): Input dataframe
        
    Returns:
        df (pandas.DataFrame): Dataframe with one-hot encoded features
    """
    df = df.copy()
    
    # Only process columns that exist in the dataframe
    cols_to_encode = [col for col in categorical_cols if col in df.columns]
    
    if cols_to_encode:
        df = pd.get_dummies(df, columns=cols_to_encode, drop_first=True)
    
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
    
    return df
