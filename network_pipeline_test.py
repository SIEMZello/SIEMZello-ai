#!/usr/bin/env python
"""
Network Traffic Anomaly Detection Pipeline Test

This script tests the complete pipeline for network traffic anomaly detection
to ensure that all components are working correctly before handing off to the backend team.
"""

import os
import sys
import pandas as pd
import numpy as np
import json
from pprint import pprint

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from network_traffic_models
from network_traffic_models.src.data.preprocessor.preprocessor import Preprocessor
from network_traffic_models.src.models.detection_model import DetectionModel
from network_traffic_models.src.models.classification_model import ClassificationModel
from network_traffic_models.network_traffic_analyzer import NetworkTrafficAnalyzer
from network_traffic_models.network_traffic_analyzer import generate_sample_data

def test_load_models():
    """Test loading the models to ensure they exist and can be loaded."""
    print("\n=== Testing Model Loading ===")
    
    # Get paths to models
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_traffic_models")
    detection_path = os.path.join(base_dir, "models", "detection_model.cbm")
    classification_path = os.path.join(base_dir, "models", "classification_model.cbm")
    
    # Test detection model loading
    try:
        print(f"Loading detection model from {detection_path}")
        detection_model = DetectionModel(detection_path)
        print("✅ Detection model loaded successfully.")
    except Exception as e:
        print(f"❌ Failed to load detection model: {e}")
        return False
        
    # Test classification model loading
    try:
        print(f"Loading classification model from {classification_path}")
        classification_model = ClassificationModel(classification_path)
        print("✅ Classification model loaded successfully.")
    except Exception as e:
        print(f"❌ Failed to load classification model: {e}")
        return False
        
    return True

def test_preprocessor():
    """Test the preprocessor on sample data."""
    print("\n=== Testing Preprocessor ===")
    
    # Generate sample data
    print("Generating sample data...")
    sample_data = generate_sample_data(5)
    print(f"Sample data shape: {sample_data.shape}")
    print(sample_data.head(2))
    
    # Initialize preprocessor with detection model
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_traffic_models")
    model_path = os.path.join(base_dir, "models", "detection_model.cbm")
    
    try:
        preprocessor = Preprocessor(model_path)
        print("✅ Preprocessor initialized successfully.")
        
        # Test preprocessing
        print("Testing preprocessing...")
        preprocessed_data = preprocessor.preprocess(sample_data)
        print(f"Preprocessed data shape: {preprocessed_data.shape}")
        print("✅ Preprocessing completed successfully.")
        
        # Verify engineered features were created
        expected_features = [
            "Speed_of_Operations_to_Data_Bytes",
            "Time_per_Process",
            "Ratio_of_Data_Flow"
        ]
        
        for feature in expected_features:
            if feature in preprocessed_data.columns:
                print(f"✅ Engineered feature '{feature}' created.")
            else:
                print(f"❌ Engineered feature '{feature}' missing.")
                return False
                
        return True
    except Exception as e:
        print(f"❌ Preprocessor test failed: {e}")
        return False

def test_full_pipeline():
    """Test the full network traffic analysis pipeline."""
    print("\n=== Testing Full Pipeline ===")
    
    try:
        # Generate sample data
        print("Generating sample data...")
        sample_data = generate_sample_data(10)
        
        # Initialize analyzer (this should load both models internally)
        print("Initializing NetworkTrafficAnalyzer...")
        analyzer = NetworkTrafficAnalyzer()
        
        # Run the analysis
        print("Running analysis...")
        results = analyzer.analyze(sample_data)
        
        # Verify results format
        if not isinstance(results, list):
            print(f"❌ Expected list of results, got {type(results)}")
            return False
            
        if len(results) != len(sample_data):
            print(f"❌ Expected {len(sample_data)} results, got {len(results)}")
            return False
            
        # Check result structure for first item
        first_result = results[0]
        required_fields = ["record_id", "is_attack", "attack_probability"]
        
        for field in required_fields:
            if field not in first_result:
                print(f"❌ Required field '{field}' missing from results")
                return False
                
        # Sample the results
        print("\nSample of analysis results:")
        for i, result in enumerate(results[:3]):  # Show first 3 results
            print(f"\nRecord {i}:")
            for k, v in result.items():
                if k == "attack_type_probabilities" and isinstance(v, dict) and len(v) > 3:
                    # Truncate large probability dictionaries
                    print(f"  {k}: {dict(list(v.items())[:3])}... (truncated)")
                else:
                    print(f"  {k}: {v}")
        
        print("\n✅ Full pipeline test passed!")
        return True
    except Exception as e:
        print(f"❌ Full pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_real_world_case():
    """Test with a more realistic case that simulates real-world traffic."""
    print("\n=== Testing with Realistic Traffic Scenario ===")
    
    # Create a more realistic traffic sample
    realistic_sample = {
        'dur': [0.5, 120.3, 0.01, 15.2, 3.5],
        'proto': ['tcp', 'tcp', 'udp', 'tcp', 'icmp'],
        'service': ['http', 'ssh', 'dns', '-', '-'],
        'state': ['CON', 'FIN', 'REQ', 'INT', 'INT'],
        'spkts': [5, 1024, 2, 50, 3],
        'dpkts': [3, 845, 1, 30, 2],
        'sbytes': [500, 102400, 200, 5000, 300],
        'dbytes': [300, 84500, 100, 3000, 200],
        'rate': [10, 1.5, 200, 5, 1],
        'sttl': [64, 128, 64, 64, 255],
        'dttl': [128, 64, 64, 128, 128],
        'sload': [0.5, 1.2, 0.1, 0.3, 0.01],
        'dload': [0.3, 0.9, 0.05, 0.2, 0.01],
        'sloss': [0, 0, 0, 1, 0],
        'dloss': [0, 0, 0, 0, 0],
        'sinpkt': [0.1, 0.12, 0.005, 0.3, 0.3],
        'dinpkt': [0.15, 0.14, 0.01, 0.5, 0.5],
        'sjit': [0.01, 0.003, 0.001, 0.05, 0.005],
        'djit': [0.02, 0.004, 0.001, 0.06, 0.01],
        'smean': [100, 100, 100, 100, 100],
        'dmean': [100, 100, 100, 100, 100]
    }
    
    df = pd.DataFrame(realistic_sample)
    
    try:
        # Initialize analyzer
        analyzer = NetworkTrafficAnalyzer()
        
        # Analyze traffic
        results = analyzer.analyze(df)
        
        # Print results
        print("\nAnalysis of realistic traffic scenario:")
        attack_count = sum(1 for r in results if r["is_attack"])
        print(f"Total records: {len(df)}")
        print(f"Detected attacks: {attack_count}")
        
        # Show the most suspicious traffic
        if results:
            sorted_results = sorted(results, key=lambda x: x['attack_probability'], reverse=True)
            most_suspicious = sorted_results[0]
            print("\nMost suspicious traffic:")
            record_id = most_suspicious['record_id']
            original_record = df.iloc[record_id].to_dict()
            
            print(f"Record ID: {record_id}")
            print(f"Protocol: {original_record['proto']}")
            print(f"Service: {original_record['service']}")
            print(f"Attack Probability: {most_suspicious['attack_probability']:.4f}")
            if most_suspicious['attack_type']:
                print(f"Attack Type: {most_suspicious['attack_type']}")
        
        print("\n✅ Realistic scenario test passed!")
        return True
    except Exception as e:
        print(f"❌ Realistic scenario test failed: {e}")
        return False

def run_all_tests():
    """Run all tests and report summary."""
    tests = [
        ("Model Loading", test_load_models),
        ("Preprocessor", test_preprocessor),
        ("Full Pipeline", test_full_pipeline),
        ("Realistic Scenario", test_real_world_case)
    ]
    
    results = []
    
    print("=" * 60)
    print("NETWORK TRAFFIC ANOMALY DETECTION PIPELINE TEST")
    print("=" * 60)
    
    for name, test_func in tests:
        print(f"\nRunning test: {name}...")
        success = test_func()
        results.append((name, success))
        
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{name}: {status}")
        if not success:
            all_passed = False
            
    if all_passed:
        print("\n✅ ALL TESTS PASSED! Your network models pipeline is ready for the backend team.")
    else:
        print("\n❌ SOME TESTS FAILED. Please fix the issues before handing off to the backend team.")

if __name__ == "__main__":
    run_all_tests()
