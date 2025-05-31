import numpy as np
import pandas as pd

# Define constants for memory log feature engineering
object_cols_to_clean = ['RDDSK', 'WRDSK', 'WCANCL', 'DSK']

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

def clean_disk_columns(df):
    """
    Clean disk-related columns that might have units (K, %) or be incorrectly typed
    
    Args:
        df (pandas.DataFrame): Input dataframe
        
    Returns:
        df (pandas.DataFrame): Dataframe with cleaned disk columns
    """
    df = df.copy()
    
    for col in object_cols_to_clean:
        if col in df.columns and df[col].dtype == 'object':
            df[col] = df[col].apply(lambda x: clean_disk_value(x))
    
    return df

def clean_disk_value(val):
    """
    Convert disk column values to appropriate numeric format
    
    Args:
        val: The value to convert
        
    Returns:
        float: The converted value
    """
    try:
        val = str(val).strip()
        
        if val.endswith('K'):
            return float(val[:-1]) * 1024
        elif val.endswith('%'):
            return float(val[:-1]) / 100
        else:
            return float(val)
    except:
        return np.nan

def encode_cmd_column(df, encoding_map=None, smoothing=10):
    """
    Apply target encoding to the CMD column
    
    Args:
        df (pandas.DataFrame): Input dataframe
        encoding_map (dict, optional): Pre-computed encoding map
        smoothing (int): Smoothing factor for target encoding
        
    Returns:
        df (pandas.DataFrame): Dataframe with encoded CMD column
        encoding_map (dict): The encoding map used
    """
    df = df.copy()
    
    if 'CMD' not in df.columns:
        return df, encoding_map
    
    if encoding_map is None:
        # Generate encoding map if one is not provided
        if 'label' in df.columns:
            global_mean = df['label'].mean()
            agg = df.groupby('CMD')['label'].agg(['mean', 'count'])
            counts = agg['count']
            means = agg['mean']
            encoding_map = {cmd: (counts[cmd] * means[cmd] + smoothing * global_mean) / (counts[cmd] + smoothing) 
                         for cmd in counts.index}
        else:
            # If no label column, use a dummy encoding
            encoding_map = {cmd: 0.5 for cmd in df['CMD'].unique()}
    
    # Apply encoding
    df['CMD_encoded'] = df['CMD'].map(encoding_map).fillna(0.5)  # Use 0.5 as default for unseen values
    
    # Drop original CMD column
    df = df.drop(columns=['CMD'])
    
    return df, encoding_map

def preprocess_features(df, cmd_encoding_map=None):
    """
    Complete preprocessing pipeline for memory log features
    
    Args:
        df (pandas.DataFrame): Raw memory log dataframe
        cmd_encoding_map (dict, optional): Pre-computed CMD encoding map
        
    Returns:
        df (pandas.DataFrame): Preprocessed dataframe ready for model input
        cmd_encoding_map (dict): The CMD encoding map used (for future use)
    """
    df = df.copy()
    
    # Drop unnecessary columns
    if 'PID' in df.columns:
        df = df.drop(columns=['PID'])
    
    # Ensure 'type' is dropped to avoid label leakage
    if 'type' in df.columns:
        df = df.drop(columns=['type'])
    
    # Apply transformations
    df = create_temporal_features(df)
    df = clean_disk_columns(df)
    
    # Remove rows with missing disk data
    df = df.dropna(subset=[col for col in object_cols_to_clean if col in df.columns])
    
    # Apply target encoding to CMD
    df, cmd_encoding_map = encode_cmd_column(df, cmd_encoding_map)
    
    return df, cmd_encoding_map
