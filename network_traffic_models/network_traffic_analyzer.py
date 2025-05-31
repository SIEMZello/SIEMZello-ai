import os
import sys
import pandas as pd
import numpy as np
import json

# Add the project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import model classes
from network_traffic_models.src.models.detection_model import DetectionModel
from network_traffic_models.src.models.classification_model import ClassificationModel

class NetworkTrafficAnalyzer:
    """
    A wrapper class for two-stage network traffic analysis:
    1. Detection - Binary classification of traffic as normal or attack
    2. Classification - Multi-class classification of attack types for flagged traffic
    """
    
    def __init__(self, detection_model_path=None, classification_model_path=None):
        """
        Initialize the analyzer with detection and classification models.
        
        Args:
            detection_model_path (str, optional): Path to detection model file
            classification_model_path (str, optional): Path to classification model file
        """
        print("Initializing NetworkTrafficAnalyzer...")
        self.detection_model = DetectionModel(model_path=detection_model_path)
        self.classification_model = ClassificationModel(model_path=classification_model_path)
        print("Models loaded successfully.")
    
    def analyze(self, traffic_data):
        """
        Analyze network traffic using the two-stage approach.
        
        Args:
            traffic_data (pd.DataFrame): Network traffic data
            
        Returns:
            list: Results containing detection and classification details
        """
        # Check if input is empty
        if traffic_data.empty:
            return []
            
        # Initialize results list
        results = []
        
        # Stage 1: Binary Detection
        print(f"Analyzing {len(traffic_data)} traffic records...")
        attack_predictions = self.detection_model.predict(traffic_data)
        attack_probabilities = self.detection_model.predict_proba(traffic_data)
        
        # Process each traffic record
        for i, (is_attack, probability) in enumerate(zip(attack_predictions, attack_probabilities)):
            result = {
                "record_id": i,
                "is_attack": bool(is_attack),
                "attack_probability": float(probability),
                "attack_type": None,
                "attack_type_probabilities": {}
            }
            
            # Stage 2: For attacks, classify the attack type
            if result["is_attack"]:
                # Extract the single record for classification
                traffic_record = traffic_data.iloc[[i]]
                
                # Get attack classification
                attack_type = self.classification_model.predict(traffic_record)[0]
                attack_type_probs = self.classification_model.predict_proba(traffic_record)[0]
                
                # Store classification results
                result["attack_type"] = str(attack_type)
                
                # If we have class probabilities, include them
                if hasattr(self.classification_model.model, 'classes_'):
                    classes = self.classification_model.model.classes_
                    result["attack_type_probabilities"] = {
                        str(cls): float(prob) for cls, prob in zip(classes, attack_type_probs)
                    }
            
            # Add result to results list
            results.append(result)
        
        print(f"Analysis complete. Found {sum(attack_predictions)} potential attacks.")
        return results
    
    def export_results(self, results, filename="analysis_results.json"):
        """
        Export analysis results to a JSON file.
        
        Args:
            results (list): Analysis results
            filename (str): Output filename
        """
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {filename}")

def generate_sample_data(n_samples=5):
    """
    Generate synthetic network traffic data for demonstration.
    
    Args:
        n_samples (int): Number of samples to generate
        
    Returns:
        pd.DataFrame: DataFrame with synthetic network traffic data
    """
    # Create synthetic data with essential features
    synthetic_data = {
        'dur': np.random.exponential(2, n_samples),
        'proto': np.random.choice(['tcp', 'udp', 'icmp'], n_samples).astype(str),
        'service': np.random.choice(['-', 'http', 'dns', 'smtp'], n_samples).astype(str),
        'state': np.random.choice(['FIN', 'CON', 'INT'], n_samples).astype(str),
        'spkts': np.random.randint(1, 100, n_samples),
        'dpkts': np.random.randint(1, 100, n_samples),
        'sbytes': np.random.randint(100, 10000, n_samples),
        'dbytes': np.random.randint(100, 10000, n_samples),
        'rate': np.random.randint(1, 100, n_samples),
        'sttl': np.random.randint(30, 255, n_samples),
        'dttl': np.random.randint(30, 255, n_samples),
        'sload': np.random.exponential(1, n_samples),
        'dload': np.random.exponential(1, n_samples),
        'sloss': np.random.randint(0, 5, n_samples),
        'dloss': np.random.randint(0, 5, n_samples),
        'sinpkt': np.random.exponential(0.1, n_samples),
        'dinpkt': np.random.exponential(0.1, n_samples),
        'sjit': np.random.exponential(0.01, n_samples),
        'djit': np.random.exponential(0.01, n_samples),
        'smean': np.random.randint(100, 1000, n_samples),
        'dmean': np.random.randint(100, 1000, n_samples)
    }
    
    return pd.DataFrame(synthetic_data)

def main():
    """Demo the NetworkTrafficAnalyzer with synthetic data."""
    # Generate sample data
    print("Generating sample network traffic data...")
    traffic_data = generate_sample_data(10)
    
    # Initialize analyzer
    analyzer = NetworkTrafficAnalyzer()
    
    # Analyze traffic
    results = analyzer.analyze(traffic_data)
    
    # Display summary
    attack_count = sum(1 for r in results if r["is_attack"])
    print(f"\nAnalysis Summary:")
    print(f"Total traffic records: {len(traffic_data)}")
    print(f"Detected attacks: {attack_count}")
    
    if attack_count > 0:
        # Show attack types
        attack_types = [r["attack_type"] for r in results if r["is_attack"]]
        attack_type_counts = {}
        for attack_type in attack_types:
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            
        print("\nDetected attack types:")
        for attack_type, count in attack_type_counts.items():
            print(f"  {attack_type}: {count}")
    
    # Export results
    analyzer.export_results(results)

if __name__ == "__main__":
    main()
