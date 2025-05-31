import pandas as pd
import numpy as np
import pickle
from catboost import Pool

from ..features.feature_engineering import (
    top_prop_categories, 
    top_service_categories, 
    top_state_categories,
    log_features,
    transform_categorical_features,
    create_engineered_features
)

class Preprocessor:
    """
    Preprocessor for network traffic data.
    
    This class handles preprocessing of network traffic data for anomaly detection models:
    - Feature engineering
    - Data type conversion
    - Categorical feature transformation
    - Feature scaling
    - Handling missing values
    
    Attributes:
        categorical_features (list): List of categorical features
        numerical_features (list): List of numerical features
        model (object): Trained model (loaded from pickle)
        selected_features (list): List of features used by the model
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the preprocessor.
        
        Args:
            model_path (str): Path to the pickled model file
        """
        self.categorical_features = ['proto', 'service', 'state']
        self.numerical_features = []
        self.model = None
        self.selected_features = None
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path):
        """
        Load model from pickle file.
        
        Args:
            model_path (str): Path to the pickled model file
        """
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
            
        # Extract feature names if available from the model
        if hasattr(self.model, 'feature_names_'):
            self.selected_features = self.model.feature_names_
    
    def identify_feature_types(self, df):
        """
        Identify numerical features.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            None
        """
        # We already know categorical features
        # Identify numerical features (excluding target variables)
        self.numerical_features = [col for col in df.columns 
                                  if col not in self.categorical_features + ['label', 'attack_cat']]
    
    def handle_outliers(self, df):
        """
        Handle outliers in numerical features using winsorization.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            DataFrame: Data with outliers handled
        """
        df = df.copy()
        for column in self.numerical_features:
            if column in df.columns:
                lower_bound = df[column].quantile(0.001)
                upper_bound = df[column].quantile(0.999)
                df.loc[:, column] = df[column].clip(lower=lower_bound, upper=upper_bound)
        return df
    
    def convert_data_types(self, df):
        """
        Convert columns to appropriate data types.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            DataFrame: Data with converted types
        """
        df = df.copy()
        
        # Convert categorical features to category type
        for col in self.categorical_features:
            if col in df.columns:
                df.loc[:, col] = df[col].astype('category')
                
        # Convert numerical features to float
        for col in self.numerical_features:
            if col in df.columns:
                df.loc[:, col] = df[col].astype(float)
                
        return df
    
    def basic_cleaning(self, df):
        """
        Perform basic cleaning on the dataset.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            DataFrame: Cleaned data
        """
        # Make a copy to avoid modifying the original dataframe
        df = df.copy()
        
        # Handle missing values in each column appropriately
        for col in df.columns:
            # Check if column is categorical
            is_cat_col = (col in self.categorical_features) or pd.api.types.is_categorical_dtype(df[col])
            
            if is_cat_col:
                # For categorical columns, convert to string and fill with '-'
                df.loc[:, col] = df[col].astype(str).fillna('-')
            else:
                # For non-categorical columns, fill with 0
                df.loc[:, col] = df[col].fillna(0)
                
        # Remove duplicates if any
        df = df.drop_duplicates()
        return df
    
    def create_log1p_features(self, df):
        """
        Apply log1p transformation to skewed numerical features.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            DataFrame: Data with log-transformed features
        """
        df = df.copy()
        
        for feature in log_features:
            if feature in df.columns:
                df.loc[:, feature] = np.log1p(df[feature].astype(float))
        
        return df
    
    def select_columns(self, df):
        """
        Select only columns that the model knows about.
        
        Args:
            df (DataFrame): Input data
            
        Returns:
            DataFrame: Data with selected columns only
        """
        if self.selected_features is not None:
            # Get intersection of dataframe columns and model features
            available_features = list(set(df.columns) & set(self.selected_features))
            return df[available_features]
        return df
    
    def preprocess(self, df):
        """
        Apply all preprocessing steps to the data.
        
        Args:
            df (DataFrame): Raw input data
            
        Returns:
            DataFrame: Fully preprocessed data
        """
        # Clean data and handle missing values
        df = self.basic_cleaning(df)
        
        # Apply feature engineering
        df = create_engineered_features(df)
        
        # Transform categorical features
        df = transform_categorical_features(df)
        
        # Apply log transformations
        df = self.create_log1p_features(df)
        
        # Identify numerical features
        self.identify_feature_types(df)
        
        # Handle outliers
        df = self.handle_outliers(df)
        
        # Convert data types
        df = self.convert_data_types(df)
        
        # One-hot encode categorical features
        df = pd.get_dummies(df, columns=self.categorical_features, drop_first=False)
        
        # Select only necessary columns
        df = self.select_columns(df)
        
        return df
    
    def create_pool(self, df):
        """
        Create a CatBoost Pool object.
        
        Args:
            df (DataFrame): Preprocessed data
            
        Returns:
            Pool: CatBoost Pool object
        """
        return Pool(data=df)
