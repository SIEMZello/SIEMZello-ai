# Define constants for feature engineering

# Top categories for categorical features (matches original repo)
top_prop_categories = ['tcp', 'udp', 'unas', 'arp', 'ospf', 'sctp']
top_service_categories = ['-', 'dns', 'http', 'smtp', 'ftp-data', 'ftp', 'ssh', 'pop3']
top_state_categories = ['INT', 'FIN', 'CON', 'REQ', 'RST']
log_features = ['smean', 'dmean', 'sinpkt', 'dinpkt', 'sload', 'dload', 'sbytes', 'dbytes', 'sjit', 'djit']

# Define the base feature set in the correct order expected by the models
base_features = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 
    'smean', 'dmean', 'trans_depth', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 
    'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_src_src_ltm'
]

# Functions for feature engineering
import numpy as np
import pandas as pd

def create_engineered_features(df):
    """
    Calculate engineered features for network traffic data
    
    Args:
        df (pandas.DataFrame): Input dataframe with network traffic features
        
    Returns:
        df (pandas.DataFrame): Dataframe with additional engineered features
    """
    df = df.copy()
    epsilon = 1e-10  # Small constant to avoid division by zero
    
    # Create new engineered features - matches original implementation
    df["Speed_of_Operations_to_Data_Bytes"] = np.log1p(df["sbytes"] / (df["dbytes"] + epsilon))
    df["Time_per_Process"] = np.log1p(df["dur"] / (df["spkts"] + epsilon))
    df["Ratio_of_Data_Flow"] = np.log1p(df["dbytes"] / (df["sbytes"] + epsilon))
    df["Ratio_of_Packet_Flow"] = np.log1p(df["dpkts"] / (df["spkts"] + epsilon))
    df["Total_Page_Errors"] = np.log1p(df["dur"] * df["sloss"])
    df["Network_Usage"] = np.log1p(df["sbytes"] + df["dbytes"])
    df["Network_Activity_Rate"] = np.log1p(df["spkts"] + df["dpkts"])
    
    return df

def calculate_engineered_features(df):
    """
    Alias for create_engineered_features for backwards compatibility
    """
    return create_engineered_features(df)

def transform_categorical_features(df, top_proto=None, top_service=None, top_state=None):
    """Transform categorical features by grouping rare categories.
    
    Args:
        df (pandas.DataFrame): DataFrame with categorical features
        top_proto (list): List of top protocol categories
        top_service (list): List of top service categories
        top_state (list): List of top state categories
        
    Returns:
        pandas.DataFrame: DataFrame with transformed categorical features
    """
    df = df.copy()
    
    # Use provided lists or defaults
    top_proto = top_proto or top_prop_categories
    top_service = top_service or top_service_categories
    top_state = top_state or top_state_categories
    
    # Transform proto category
    if 'proto' in df.columns:
        df['proto'] = df['proto'].apply(lambda x: x if x in top_proto else '-')
    
    # Transform service category
    if 'service' in df.columns:
        df['service'] = df['service'].apply(lambda x: x if x in top_service else '-')
    
    # Transform state category
    if 'state' in df.columns:
        df['state'] = df['state'].apply(lambda x: x if x in top_state else '-')
    
    return df

def ensure_feature_order(df, feature_names=None):
    """
    Ensure the dataframe columns are in the expected order for the model
    
    Args:
        df (pandas.DataFrame): Input dataframe
        feature_names (list): List of expected feature names in order
        
    Returns:
        pandas.DataFrame: Reordered dataframe
    """
    if feature_names is None:
        return df
    
    # Create missing columns with default values
    for col in feature_names:
        if col not in df.columns:
            if col in ['proto', 'service', 'state']:
                df[col] = '-'
            else:
                df[col] = 0
    
    # Return only the columns needed by the model in the correct order
    return df[feature_names]
