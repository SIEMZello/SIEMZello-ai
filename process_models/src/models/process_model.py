import os
import sys
import joblib
import numpy as np
import pandas as pd

# Add the project root to sys.path to fix import issues
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(root_dir)

from process_models.src.features.feature_engineering import preprocess_features

class ProcessModel:
    """
    XGBoost model for binary classification of process logs (normal vs. anomalous).
    """
    
    def __init__(self, model_path=None):
        """Initialize the process model with the model path."""
        # Get the absolute path to the model file
        if model_path is None:
            # First, try finding the model in the models subdirectory
            self.model_path = os.path.join(root_dir, "models", "process_model.joblib")
            
            # If not found, try using the one in the root directory
            if not os.path.exists(self.model_path):
                self.model_path = os.path.join(root_dir, "..", "xgb_process_model.joblib")
        else:
            self.model_path = model_path
            
        print(f"Using process model: {self.model_path}")
        
        # Load the model
        self.load_model()
        
    def load_model(self):
        """Load the model from disk."""
        try:
            self.model = joblib.load(self.model_path)
            print(f"Model loaded successfully from {self.model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
    
    def predict(self, df):
        """
        Predict if process logs are anomalous (1) or normal (0).
        
        Args:
            df (pandas.DataFrame): Process log data
            
        Returns:
            numpy.ndarray: Binary predictions (0 for normal, 1 for anomalous)
        """
        try:
            # Preprocess the data
            df_processed = preprocess_features(df)
            
            # Make predictions
            predictions = self.model.predict(df_processed)
            
            return predictions
        except Exception as e:
            print(f"Error in prediction: {e}")
            # Return default predictions (all 0) if prediction fails
            return np.zeros(len(df))
    
    def predict_proba(self, df):
        """
        Get probability estimates for process logs being anomalous.
        
        Args:
            df (pandas.DataFrame): Process log data
            
        Returns:
            numpy.ndarray: Probability of anomaly for each record
        """
        try:
            # Preprocess the data
            df_processed = preprocess_features(df)
            
            # Get probability estimates
            probabilities = self.model.predict_proba(df_processed)[:, 1]
            
            return probabilities
        except Exception as e:
            print(f"Error in probability prediction: {e}")
            # Return default probabilities (all 0) if prediction fails
            return np.zeros(len(df))
