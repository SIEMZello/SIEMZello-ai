import os
import sys
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import pickle

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def inspect_model_features(model_path):
    """
    Inspect the features expected by a model.
    
    Args:
        model_path (str): Path to the model file
    """
    print(f"Inspecting model at {model_path}")
    
    # Try loading as CatBoost model
    try:
        model = CatBoostClassifier()
        model.load_model(model_path)
        print("Successfully loaded as CatBoost model (.cbm)")
        
        # Print feature information
        print(f"Number of features: {len(model.feature_names_)}")
        print(f"First 10 features: {model.feature_names_[:10]}")
        
        return model.feature_names_
    except Exception as e:
        print(f"Failed to load as CatBoost model: {e}")
        
        # Try loading as pickle
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            print("Successfully loaded as pickle file")
            
            if hasattr(model, 'feature_names_'):
                print(f"Number of features: {len(model.feature_names_)}")
                print(f"First 10 features: {model.feature_names_[:10]}")
                return model.feature_names_
            else:
                print("Model does not have feature_names_ attribute")
                return None
        except Exception as e2:
            print(f"Failed to load as pickle: {e2}")
            return None

def generate_test_sample(feature_names=None):
    """
    Generate a test sample with the right feature names.
    
    Args:
        feature_names (list): List of feature names to include
        
    Returns:
        pd.DataFrame: Sample dataframe
    """
    if feature_names:
        # Create a sample with all the required features
        sample_data = {}
        for feature in feature_names:
            if feature in ['proto', 'service', 'state']:
                sample_data[feature] = ['tcp' if feature == 'proto' else
                                       'http' if feature == 'service' else 'FIN']
            else:
                sample_data[feature] = [np.random.rand()]
                
        return pd.DataFrame(sample_data)
    else:
        # Create a generic sample with common network traffic features
        return pd.DataFrame({
            'dur': [np.random.exponential(2)],
            'proto': ['tcp'],
            'service': ['http'],
            'state': ['FIN'],
            'spkts': [np.random.randint(1, 100)],
            'dpkts': [np.random.randint(1, 100)],
            'sbytes': [np.random.randint(100, 10000)],
            'dbytes': [np.random.randint(100, 10000)]
        })

def try_model_prediction(model_path, sample_data):
    """
    Try making a prediction with the model.
    
    Args:
        model_path (str): Path to the model file
        sample_data (pd.DataFrame): Sample data to predict
    """
    print("\nTrying prediction with sample data...")
    
    # Try as CatBoost
    try:
        model = CatBoostClassifier()
        model.load_model(model_path)
        prediction = model.predict(sample_data)
        print(f"Prediction successful: {prediction}")
        return True
    except Exception as e:
        print(f"CatBoost prediction failed: {e}")
        
        # Try as pickle
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            prediction = model.predict(sample_data)
            print(f"Pickle prediction successful: {prediction}")
            return True
        except Exception as e2:
            print(f"Pickle prediction failed: {e2}")
            return False

def main():
    """Main function to test model loading and prediction"""
    # Define model paths
    root_dir = os.path.dirname(os.path.abspath(__file__))
    detection_model_path = os.path.join(root_dir, "models", "detection_model.cbm")
    classification_model_path = os.path.join(root_dir, "models", "classification_model.cbm")
    
    # Try alternate extensions if .cbm files don't exist
    if not os.path.exists(detection_model_path):
        for ext in ['.pkl', '.model']:
            alt_path = os.path.join(root_dir, "models", f"detection_model{ext}")
            if os.path.exists(alt_path):
                detection_model_path = alt_path
                break
    
    if not os.path.exists(classification_model_path):
        for ext in ['.pkl', '.model']:
            alt_path = os.path.join(root_dir, "models", f"classification_model{ext}")
            if os.path.exists(alt_path):
                classification_model_path = alt_path
                break
    
    # Inspect detection model
    print("\n===== DETECTION MODEL =====")
    detection_features = inspect_model_features(detection_model_path)
    
    # Generate and test with sample data for detection
    detection_sample = generate_test_sample(detection_features)
    try_model_prediction(detection_model_path, detection_sample)
    
    # Inspect classification model
    print("\n===== CLASSIFICATION MODEL =====")
    classification_features = inspect_model_features(classification_model_path)
    
    # Generate and test with sample data for classification
    classification_sample = generate_test_sample(classification_features)
    try_model_prediction(classification_model_path, classification_sample)

if __name__ == "__main__":
    main()
