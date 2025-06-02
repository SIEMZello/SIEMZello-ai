import os
import sys
import pandas as pd
import numpy as np
import json



current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
'''
# Add the project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
'''
# Import model class
from memory_models.src.models.memory_model import MemoryModel

class MemoryAnalyzer:
    """
    A wrapper class for memory log anomaly detection.
    """
    
    def __init__(self, model_path=None, cmd_encoding_map_path=None):
        """
        Initialize the analyzer with the memory model.
        
        Args:
            model_path (str, optional): Path to memory model file
            cmd_encoding_map_path (str, optional): Path to CMD encoding map file
        """
        print("Initializing MemoryAnalyzer...")
        self.memory_model = MemoryModel(model_path=model_path, cmd_encoding_map_path=cmd_encoding_map_path)
        print("Model loaded successfully.")
    
    def analyze(self, memory_data):
        """
        Analyze memory logs for anomalies.
        
        Args:
            memory_data (pd.DataFrame): Memory log data
            
        Returns:
            list: Results containing detection details
        """
        # Check if input is empty
        if memory_data.empty:
            return []
            
        # Initialize results list
        results = []
        
        # Binary Detection
        print(f"Analyzing {len(memory_data)} memory records...")
        anomaly_predictions = self.memory_model.predict(memory_data)
        anomaly_probabilities = self.memory_model.predict_proba(memory_data)
        
        # Process each log record
        for i, (is_anomaly, probability) in enumerate(zip(anomaly_predictions, anomaly_probabilities)):
            result = {
                "record_id": i,
                "is_anomaly": bool(is_anomaly),
                "anomaly_probability": float(probability)
            }
            
            # Add the original memory details for context
            important_cols = ['ts', 'CMD', 'RDDSK', 'WRDSK', 'DSK'] 
            for col in important_cols:
                if col in memory_data.columns:
                    result[col] = str(memory_data.iloc[i][col])
            
            # Add result to results list
            results.append(result)
        
        print(f"Analysis complete. Found {sum(anomaly_predictions)} potential anomalies.")
        return results
    
    def export_results(self, results, filename="memory_analysis_results.json"):
        """
        Export analysis results to a JSON file.
        
        Args:
            results (list): Analysis results
            filename (str): Output filename
        """
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {filename}")


def generate_sample_data(num_samples=5):
    """
    Generate sample memory data for testing.
    
    Args:
        num_samples (int): Number of sample records to generate
        
    Returns:
        pd.DataFrame: Sample memory data
    """
    import numpy as np
    import pandas as pd
    
    # Generate random data
    data = {
        'PID': np.random.randint(1, 10000, size=num_samples),
        'ts': np.random.randint(1600000000, 1610000000, size=num_samples),
        'CMD': np.random.choice(['systemd', 'bash', 'python3', 'chrome', 'sshd'], size=num_samples),
        'RDDSK': [f"{np.random.randint(1, 500)}K" for _ in range(num_samples)],
        'WRDSK': [f"{np.random.randint(1, 300)}K" for _ in range(num_samples)],
        'WCANCL': [f"{np.random.randint(0, 10)}" for _ in range(num_samples)],
        'DSK': [f"{np.random.randint(1, 100)}%" for _ in range(num_samples)]
    }
    
    return pd.DataFrame(data)
