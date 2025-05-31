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

# Suppress CatBoost warnings
warnings.filterwarnings('ignore', category=UserWarning)

from network_traffic_models.src.data.preprocessor.preprocessor import Preprocessor

class DetectionModel:
    """
    CatBoost model for binary classification of network traffic (normal vs. attack).
    """
    
    def __init__(self, model_path=None):
        """Initialize the detection model with the model path."""
        # Get the absolute path to the model file
        if model_path is None:
            self.model_path = os.path.join(root_dir, "models", "detection_model.cbm")
            # Try alternate extensions if .cbm file doesn't exist
            if not os.path.exists(self.model_path):
                for ext in ['.pkl', '.model']:
                    alt_path = os.path.join(root_dir, "models", f"detection_model{ext}")
                    if os.path.exists(alt_path):
                        self.model_path = alt_path
                        break
        else:
            self.model_path = model_path
            
        print(f"Using detection model: {self.model_path}")
        
        # Initialize preprocessor with model path
        self.preprocessor = Preprocessor(self.model_path)
        
        # Store the model from the preprocessor
        self.model = self.preprocessor.model
        
    def predict(self, df):
        """Predict if traffic records are attacks (1) or normal (0)."""
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
            print(f"Error in detection prediction: {e}")
            # Return default predictions (all 0) if prediction fails
            return np.zeros(len(df))
    
    def predict_proba(self, df):
        """Get probability estimates for traffic being an attack."""
        try:
            # Preprocess the data
            df_processed = self.preprocessor.preprocess(df)
            
            # Create pool for prediction
            data_pool = self.preprocessor.create_pool(df_processed)
            
            # Make probability predictions (get probability for positive class)
            probabilities = self.model.predict_proba(data_pool)
            
            # Return only probabilities for positive class (attack)
            if isinstance(probabilities, np.ndarray) and probabilities.ndim > 1 and probabilities.shape[1] > 1:
                return probabilities[:, 1]
            return probabilities
        except Exception as e:
            print(f"Error in detection probability prediction: {e}")
            # Return default probabilities (all 0) if prediction fails
            return np.zeros(len(df))
