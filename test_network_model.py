#!/usr/bin/env python
"""
Network Model Tester

This script demonstrates how to use the network traffic model
to analyze a specific JSON log entry.
"""

import os
import sys
import json
import time
import pandas as pd
from pprint import pprint

# Make sure the models are in the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the network traffic analyzer
try:
    from network_traffic_models.network_traffic_analyzer import NetworkTrafficAnalyzer
except ImportError as e:
    print(f"Error importing NetworkTrafficAnalyzer: {e}")
    print("Make sure the network_traffic_models directory is in your path")
    sys.exit(1)

def test_network_log(log_entry, verbose=True):
    """
    Test a single network log entry with the NetworkTrafficAnalyzer.
    
    Args:
        log_entry (dict): The network log entry in JSON format
        verbose (bool): Whether to print detailed information
        
    Returns:
        dict: The analysis result
    """
    if verbose:
        print("\n" + "=" * 50)
        print("NETWORK TRAFFIC ANALYZER TEST")
        print("=" * 50)
        print("\nInitializing network traffic analyzer...")
      # pandas is already imported at the top of the file
    
    start_time = time.time()
    # Initialize the analyzer
    analyzer = NetworkTrafficAnalyzer()
    init_time = time.time() - start_time
    
    if verbose:
        print(f"Initialization completed in {init_time:.2f} seconds")
        print("\nAnalyzing network log entry:")
        print("-" * 50)
        pprint(log_entry)
        print("-" * 50)
    
    # Convert the dictionary to a pandas DataFrame
    df = pd.DataFrame([log_entry])
    
    # Analyze the log entry
    start_time = time.time()
    results = analyzer.analyze(df)
    analysis_time = time.time() - start_time
    
    # Get the first result since we're only analyzing one log entry
    if results and isinstance(results, list) and len(results) > 0:
        result = results[0]
    else:
        result = {"is_attack": False, "attack_probability": 0, "attack_type": "N/A"}
    
    if verbose:
        print(f"\nAnalysis completed in {analysis_time:.4f} seconds")
        print("\nRESULTS:")
        print("-" * 50)
        pprint(result)
        print("-" * 50)
        
        # Highlight key information
        is_attack = result.get("is_attack", False)
        attack_prob = result.get("attack_probability", 0) * 100
        attack_type = result.get("attack_type", "N/A")
        
        print(f"\nATTACK DETECTED: {is_attack}")
        print(f"ATTACK PROBABILITY: {attack_prob:.2f}%")
        print(f"ATTACK TYPE: {attack_type}")
    
    return result

def main():
    """Main function to test the network model with a specific log entry"""
    # The specific log entry to test
    log_entry ={
  "dur": 7.684661865234375,
  "proto": "tcp",
  "service": "-",
  "state": "REQ",
  "spkts": 12,
  "dpkts": 16,
  "sbytes": 1289,
  "dbytes": 1719,
  "rate": 2.0820694886244047,
  "sttl": 64,
  "dttl": 64,
  "sload": 1341.893785418429,
  "dload": 1789.5387254726759,
  "sloss": 0,
  "dloss": 0,
  "sinpkt": 0.0,
  "dinpkt": 0.512310791015625,
  "sjit": 0.0,
  "djit": 0.9801400742629638,
  "swin": 502,
  "dwin": 502,
  "stcpb": 620576699,
  "dtcpb": 620576699,
  "tcprtt": 0.0,
  "synack": 0.0,
  "ackdat": 0.0,
  "smean": 107.41666666666667,
  "dmean": 107.4375,
  "trans_depth": 0,
  "is_sm_ips_ports": 0,
  "ct_state_ttl": 4,
  "ct_flw_http_mthd": 0,
  "is_ftp_login": 0,
  "ct_ftp_cmd": 0,
  "ct_srv_src": 1,
  "ct_srv_dst": 3,
  "ct_dst_ltm": 3,
  "ct_src_ltm": 1,
  "ct_src_dport_ltm": 1,
  "ct_dst_sport_ltm": 1,
  "ct_src_src_ltm": 1
}
    
    # Test with the specific log entry
    result = test_network_log(log_entry)
    
    # Save result to file for reference
    with open("network_analysis_result.json", "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"\nResult saved to: {os.path.abspath('network_analysis_result.json')}")
    
    # Demonstration of how to test a batch of logs
    print("\n\nDEMONSTRATION: How to process a batch of logs")
    print("-" * 50)
    print("""
# Sample code to process logs from a JSON file
import json
import pandas as pd

# Load logs from file
with open('your_logs.json', 'r') as f:
    logs = json.load(f)

# Method 1: Process logs one by one
print("Method 1: Processing logs one by one")
results = []
for log in logs:
    result = test_network_log(log, verbose=False)
    results.append(result)
    
# Method 2: Process all logs at once (more efficient for large datasets)
print("\nMethod 2: Processing all logs at once (more efficient)")
# Convert all logs to a pandas DataFrame
logs_df = pd.DataFrame(logs)
analyzer = NetworkTrafficAnalyzer()
batch_results = analyzer.analyze(logs_df)

# Count attacks
individual_attack_count = sum(1 for r in results if r.get('is_attack', False))
batch_attack_count = sum(1 for r in batch_results if r.get('is_attack', False))
print(f"Processed {len(logs)} logs:")
print(f"- Individual processing: detected {individual_attack_count} attacks")
print(f"- Batch processing: detected {batch_attack_count} attacks")
""")

if __name__ == "__main__":
    main()
