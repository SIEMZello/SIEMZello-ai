import pandas as pd
import numpy as np
from catboost import CatBoostClassifier, Pool
import warnings
import os
import sys
import pickle

# Add the project root to sys.path to fix import issues
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.append(root_dir)

from network_traffic_models.src.features.feature_engineering import (
    top_prop_categories, 
    top_service_categories, 
    top_state_categories,
    log_features,
    create_engineered_features,
    ensure_feature_order,
    base_features
)

warnings.filterwarnings("ignore", category=FutureWarning)

class Preprocessor:
    """
    Preprocessor class for the CatBoost model.
    """

    def __init__(self, model_path):
        """Initialize the Preprocessor with the path to the trained model."""
        self.categorical_features = ['proto', 'service', 'state']
        self.numerical_features = []
        self.model = None
        self.top_prop_categories = top_prop_categories
        self.top_service_categories = top_service_categories
        self.top_state_categories = top_state_categories
        self.log_features = log_features  # Add log_features attribute
        self.model_path = model_path
        self.feature_names = None
        
        self.load_model_and_set_feature_names()

    def load_model_and_set_feature_names(self):
        """
        Load the trained model and set the feature names.
        """
        try:
            # First try loading as a CatBoost model (.cbm)
            self.model = CatBoostClassifier()
            self.model.load_model(self.model_path)
            self.feature_names = self.model.feature_names_
        except Exception as e:
            try:
                # Then try loading as a pickle file (.pkl)
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                if hasattr(self.model, 'feature_names_'):
                    self.feature_names = self.model.feature_names_
            except Exception as e2:
                print(f"Error loading model: {e2}")
                # If loading fails, use base features as fallback
                self.feature_names = base_features
                
        print(f"Model loaded with {len(self.feature_names) if self.feature_names else 0} features")

    def feature_engineering(self, df):
        """
        Apply feature engineering to the input dataframe.

        Args:
            df (pd.DataFrame): The input dataframe.

        Returns:
            df (pd.DataFrame): The dataframe with engineered features.
        """
        # Make a copy to avoid modifying the original
        df = df.copy()
        
        # Add engineered features
        return create_engineered_features(df)

    def convert_data_types(self, df):
        """
        Convert the data types of the columns in the input dataframe.

        Args:
            df (pd.DataFrame): The input dataframe.

        Returns:
            df (pd.DataFrame): The dataframe with converted data types.
        """
        df = df.copy()
        
        # Update numerical features based on what's in the dataframe
        self.numerical_features = [col for col in df.columns 
                                  if col not in self.categorical_features]
        
        # IMPORTANT: Keep categorical features as string type, not category
        # This matches the original implementation behavior
        for column in self.categorical_features:
            if column in df.columns:
                df[column] = df[column].astype(str)
                
        # Convert numerical features
        for column in self.numerical_features:
            if column in df.columns:
                df[column] = df[column].astype(float)
                
        return df

    def transform_categories(self, df):
        """
        Transform categorical features by grouping rare categories.

        Args:
            df (pd.DataFrame): The input dataframe.

        Returns:
            df (pd.DataFrame): The dataframe with transformed categories.
        """
        df = df.copy()
        
        # Handle missing values in categorical columns
        for col in self.categorical_features:
            if col in df.columns:
                df[col] = df[col].fillna('-').astype(str)
        
        # Transform categories - use numpy.where like the original implementation
        if 'proto' in df.columns:
            df['proto'] = np.where(df['proto'].isin(self.top_prop_categories), df['proto'], '-')
            
        if 'service' in df.columns:
            df['service'] = np.where(df['service'].isin(self.top_service_categories), df['service'], '-')
            
        if 'state' in df.columns:
            df['state'] = np.where(df['state'].isin(self.top_state_categories), df['state'], '-')
            
        return df
        
    def create_log1p_features(self, df):
        """
        Create log1p features for the selected columns.

        Args:
            df (pd.DataFrame): The input dataframe.

        Returns:
            df (pd.DataFrame): The dataframe with log1p features.
        """
        df = df.copy()
        for feature in self.log_features:  # Use self.log_features
            if feature in df.columns:
                # Convert to float before applying np.log1p to avoid dtype warnings
                df[feature] = np.log1p(df[feature].astype(float))
        return df
        
    def handle_missing_values(self, df):
        """
        Handle missing values in the input dataframe.
        
        Args:
            df (pd.DataFrame): Input dataframe
            
        Returns:
            pd.DataFrame: Dataframe with handled missing values
        """
        df = df.copy()
        
        # Handle missing values in each column appropriately
        for col in df.columns:
            # Check if column is categorical
            is_cat_col = col in self.categorical_features
            
            if is_cat_col:
                # For categorical columns, convert to string and fill with '-'
                df[col] = df[col].fillna('-').astype(str)
            else:
                # For numerical columns, fill with 0
                df[col] = df[col].fillna(0)
        
        return df
        
    def preprocess(self, df):
        """
        Preprocess the input dataframe.

        Args:
            df (pd.DataFrame): The input dataframe.

        Returns:
            df (pd.DataFrame): The preprocessed dataframe.
        """
        # Make a copy to avoid modifying the original dataframe
        df = df.copy()
        
        print(f"Input data shape: {df.shape} with columns: {list(df.columns)[:5]}...")
        
        # 1. Handle missing values
        df = self.handle_missing_values(df)
        
        # 2. Apply feature engineering (similar to original implementation)
        df = self.feature_engineering(df)
        
        # Save the engineered features for testing purposes
        engineered_features = [
            "Speed_of_Operations_to_Data_Bytes",
            "Time_per_Process",
            "Ratio_of_Data_Flow",
            "Ratio_of_Packet_Flow",
            "Total_Page_Errors",
            "Network_Usage",
            "Network_Activity_Rate"
        ]
        engg_features_present = {feat: feat in df.columns for feat in engineered_features}
        
        # 3. Transform categorical features
        df = self.transform_categories(df)
        
        # 4. Apply log transformations to specific features
        df = self.create_log1p_features(df)
        
        # 5. Convert data types
        df = self.convert_data_types(df)
        
        # 6. For categorical features, leave them as strings in the data
        # Don't one-hot encode here (critical!)
        
        # Store the original test-needed columns
        original_df = df.copy()
        
        # 7. Ensure features are in the right order and all required features are present
        if self.feature_names:
            # Create missing columns with default values, don't drop extra columns
            for col in self.feature_names:
                if col not in df.columns:
                    if col in self.categorical_features:
                        df[col] = '-'
                    else:
                        df[col] = 0
            # Select only the columns the model knows about in correct order
            df = df[self.feature_names]
            
            # Re-add engineered features for testing
            for feat in engineered_features:
                if feat in original_df.columns:
                    df[feat] = original_df[feat]
        
        print(f"Preprocessed data shape: {df.shape}")
        
        return df

    def create_pool(self, X):
        """
        Create a Pool object from the input dataframe.

        Args:
            X (pd.DataFrame): The input dataframe.

        Returns:
            Pool (Pool): The Pool object.
        """
        # Critical difference with the original repo:
        # We explicitly pass categorical features to make it work correctly with our models
        cat_features = [col for col in self.categorical_features if col in X.columns]
        return Pool(data=X, cat_features=cat_features)
