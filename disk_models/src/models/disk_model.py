import os
import sys
import joblib
import pickle
import numpy as np
import pandas as pd

# Add the project root to sys.path to fix import issues
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(root_dir)

from disk_models.src.features.feature_engineering import preprocess_features

class DiskModel:
    """
    XGBoost model for binary classification of disk logs (normal vs. anomalous).
    """
    
    def __init__(self, model_path=None, cmd_encoding_map_path=None):
        """Initialize the disk model with the model path."""
        # Get the absolute path to the model file
        if model_path is None:
            # First, try finding the model in the models subdirectory
            self.model_path = os.path.join(root_dir, "models", "disk_model.pkl")
            
            # If not found, try using the one in the root directory
            if not os.path.exists(self.model_path):
                self.model_path = os.path.join(root_dir, "..", "xgboost_disk_model.pkl")
        else:
            self.model_path = model_path
            
        print(f"Using disk model: {self.model_path}")
        
        # Try to load the CMD encoding map if provided
        self.cmd_encoding_map = None
        if cmd_encoding_map_path and os.path.exists(cmd_encoding_map_path):
            try:
                with open(cmd_encoding_map_path, 'rb') as f:
                    self.cmd_encoding_map = pickle.load(f)
                print(f"CMD encoding map loaded from {cmd_encoding_map_path}")
            except Exception as e:
                print(f"Error loading CMD encoding map: {e}")
        
        # Load the model
        self.load_model()
        
    def load_model(self):
        """Load the model from disk."""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"Model loaded successfully from {self.model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
    
    def predict(self, df):
        """
        Predict if disk logs are anomalous (1) or normal (0).
        
        Args:
            df (pandas.DataFrame): Disk log data
            
        Returns:
            numpy.ndarray: Binary predictions (0 for normal, 1 for anomalous)
        """
        try:
            # Preprocess the data
            df_processed, _ = preprocess_features(df, self.cmd_encoding_map)
            
            # Make predictions
            predictions = self.model.predict(df_processed)
            
            return predictions
        except Exception as e:
            print(f"Error in prediction: {e}")
            # Return default predictions (all 0) if prediction fails
            return np.zeros(len(df))
    
    def predict_proba(self, df):
        """
        Get probability estimates for disk logs being anomalous.
        
        Args:
            df (pandas.DataFrame): Disk log data
            
        Returns:
            numpy.ndarray: Probability of anomaly for each record
        """
        try:
            # Preprocess the data
            df_processed, _ = preprocess_features(df, self.cmd_encoding_map)
            
            # Get probability estimates
            probabilities = self.model.predict_proba(df_processed)[:, 1]
            
            return probabilities
        except Exception as e:
            print(f"Error in probability prediction: {e}")
            # Return default probabilities (all 0) if prediction fails
            return np.zeros(len(df))
