import os
import sys
import pandas as pd
import numpy as np
import pickle
import warnings

# Add the project root to sys.path to fix import issues
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
parent_dir = os.path.abspath(os.path.join(root_dir, '..'))
sys.path.append(parent_dir)

# Import CatBoost
from catboost import CatBoostClassifier, Pool

# Suppress CatBoost warnings
warnings.filterwarnings('ignore', category=UserWarning)

from network_traffic_models.src.data.preprocessor.preprocessor import Preprocessor

class ClassificationModel:
    """
    Model for classifying the type of network traffic attack.
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the classification model.
        
        Args:
            model_path (str, optional): Path to model file. If None, uses default path.
        """
        # Set default model path if none provided
        if model_path is None:
            # Get the current directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "..", "..", "models", "classification_model.cbm")
        
        self.model_path = model_path
        self.model = None
        self.preprocessor = None
        
        # Initialize model and preprocessor
        self._initialize()
        
    def _initialize(self):
        """Initialize the model and preprocessor."""
        try:
            # Load the model
            self.model = CatBoostClassifier()
            self.model.load_model(self.model_path)
            
            # Create the preprocessor
            self.preprocessor = Preprocessor(self.model_path)
            print(f"Classification model loaded from {self.model_path}")
        except Exception as e:
            print(f"Error loading classification model: {e}")
            # Create a dummy model for testing
            self.model = CatBoostClassifier(
                loss_function='MultiClass',
                iterations=10,
                depth=2,
                verbose=False
            )
            print("Using dummy classification model for testing")
            
            # Create the preprocessor anyway
            self.preprocessor = Preprocessor(self.model_path)
    
    def predict(self, df):
        """Predict the attack category for given traffic records."""
        try:
            # Preprocess the data - don't one-hot encode (key difference)
            df_processed = self.preprocessor.preprocess(df)
            
            # Create pool for prediction - DO pass categorical features
            data_pool = self.preprocessor.create_pool(df_processed)
            
            # Make predictions
            predictions = self.model.predict(data_pool)
            
            # Ensure predictions are flattened if they're in a 2D array
            if isinstance(predictions, np.ndarray) and predictions.ndim > 1:
                predictions = predictions.flatten()
                
            return predictions
        except Exception as e:
            print(f"Error in classification prediction: {e}")
            # Return default predictions (all 'Normal') if prediction fails
            return np.array(['Normal'] * len(df))
    
    def predict_proba(self, df):
        """Predict probabilities for each attack category."""
        try:
            # Preprocess the data
            df_processed = self.preprocessor.preprocess(df)
            
            # Create pool for prediction
            data_pool = self.preprocessor.create_pool(df_processed)
            
            # Make probability predictions
            return self.model.predict_proba(data_pool)
        except Exception as e:
            print(f"Error in probability prediction: {e}")
            # Return empty array if prediction fails
            return np.array([])
