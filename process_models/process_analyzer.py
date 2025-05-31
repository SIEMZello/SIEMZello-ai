import os
import sys
import pandas as pd
import numpy as np
import json

# Add the project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import model class
from process_models.src.models.process_model import ProcessModel

class ProcessAnalyzer:
    """
    A wrapper class for process log anomaly detection.
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the analyzer with the process model.
        
        Args:
            model_path (str, optional): Path to process model file
        """
        print("Initializing ProcessAnalyzer...")
        self.process_model = ProcessModel(model_path=model_path)
        print("Model loaded successfully.")
    
    def analyze(self, process_data):
        """
        Analyze process logs for anomalies.
        
        Args:
            process_data (pd.DataFrame): Process log data
            
        Returns:
            list: Results containing detection details
        """
        # Check if input is empty
        if process_data.empty:
            return []
            
        # Initialize results list
        results = []
        
        # Binary Detection
        print(f"Analyzing {len(process_data)} process records...")
        anomaly_predictions = self.process_model.predict(process_data)
        anomaly_probabilities = self.process_model.predict_proba(process_data)
        
        # Process each log record
        for i, (is_anomaly, probability) in enumerate(zip(anomaly_predictions, anomaly_probabilities)):
            result = {
                "record_id": i,
                "is_anomaly": bool(is_anomaly),
                "anomaly_probability": float(probability)
            }
            
            # Add the original process details for context
            for col in process_data.columns:
                if col in ['PID', 'ts', 'CMD', 'TRUN', 'CPU']:
                    result[col] = str(process_data.iloc[i][col])
            
            # Add result to results list
            results.append(result)
        
        print(f"Analysis complete. Found {sum(anomaly_predictions)} potential anomalies.")
        return results
    
    def export_results(self, results, filename="process_analysis_results.json"):
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
    Generate sample process data for testing.
    
    Args:
        num_samples (int): Number of sample records to generate
        
    Returns:
        pd.DataFrame: Sample process data
    """
    import numpy as np
    import pandas as pd
      # Generate random data
    data = {
        'PID': np.random.randint(1, 10000, size=num_samples),
        'ts': np.random.randint(1600000000, 1610000000, size=num_samples),
        'CMD': np.random.choice(['systemd', 'bash', 'python3', 'chrome', 'sshd'], size=num_samples),
        'TRUN': np.random.exponential(1000, size=num_samples),
        'TSLPI': np.random.exponential(500, size=num_samples),
        'TSLPU': np.random.exponential(100, size=num_samples),
        'POLI': np.random.choice(['0', 'norm'], size=num_samples),  # Updated to match model's expected values
        'NICE': np.random.randint(-20, 20, size=num_samples),
        'PRI': np.random.randint(0, 100, size=num_samples),
        'RTPR': np.random.randint(0, 10, size=num_samples),
        'CPUNR': np.random.randint(0, 8, size=num_samples),
        'Status': np.random.choice(['0', 'C', 'N', 'NC', 'NE', 'NS'], size=num_samples),  # Updated to match model's expected values
        'EXC': np.random.exponential(10, size=num_samples),
        'State': np.random.choice(['E', 'R', 'S', 'T', 'Z'], size=num_samples),  # Updated to match model's expected values
        'CPU': np.random.exponential(5, size=num_samples)
    }
    
    return pd.DataFrame(data)
