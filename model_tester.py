#!/usr/bin/env python
"""
SIEM Model Tester

This script demonstrates how to ingest JSON logs into the SIEM models 
and view the outputs. It provides simple examples for each model type.

Usage:
    python model_tester.py --model [process|memory|disk|network|all] --input [path/to/logs.json]
"""

import os
import sys
import json
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from pprint import pprint

# Add the current directory to the path to ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the analyzers
try:
    from process_models.process_analyzer import ProcessAnalyzer
    from memory_models.memory_analyzer import MemoryAnalyzer
    from disk_models.disk_analyzer import DiskAnalyzer
    from network_traffic_models.network_traffic_analyzer import NetworkTrafficAnalyzer
except ImportError as e:
    print(f"Error importing models: {e}")
    print("Make sure all required packages are installed: pip install -r requirements.txt")
    sys.exit(1)

# Constants for pretty printing
HEADER = '\033[95m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

def print_header(text):
    """Print a formatted header"""
    print(f"\n{BOLD}{BLUE}{'=' * 80}{ENDC}")
    print(f"{BOLD}{BLUE}{text.center(80)}{ENDC}")
    print(f"{BOLD}{BLUE}{'=' * 80}{ENDC}\n")

def print_section(text):
    """Print a formatted section header"""
    print(f"\n{BOLD}{YELLOW}{'-' * 80}{ENDC}")
    print(f"{BOLD}{YELLOW}{text}{ENDC}")
    print(f"{BOLD}{YELLOW}{'-' * 80}{ENDC}\n")

def print_result(result, is_anomaly=None):
    """Print a formatted result with appropriate coloring"""
    if isinstance(result, dict):
        # Determine if this is an anomaly/attack
        if is_anomaly is None:
            is_anomaly = result.get('is_anomaly', result.get('is_attack', False))
            
        # Set color based on anomaly status
        color = RED if is_anomaly else GREEN
        
        # Get probability if available
        prob = result.get('anomaly_probability', result.get('attack_probability', None))
        prob_str = f"{prob:.2%}" if prob is not None else "N/A"
        
        # Print header with anomaly status
        status = "ANOMALY DETECTED" if is_anomaly else "NORMAL ACTIVITY"
        print(f"{BOLD}{color}[{status}] Probability: {prob_str}{ENDC}")
        
        # Filter out very large fields for cleaner output
        filtered_result = {k: v for k, v in result.items() if not isinstance(v, (bytes, bytearray)) 
                          and not (isinstance(v, str) and len(v) > 500)}
        
        # Print the content
        pprint(filtered_result)
    else:
        print(result)
    print()

def load_json_logs(file_path):
    """Load JSON logs from a file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON logs from {file_path}: {e}")
        return None

def test_process_analyzer(logs):
    """Test the process analyzer with the provided logs"""
    print_header("PROCESS ANALYZER TEST")
    
    try:
        print_section("Initializing ProcessAnalyzer")
        analyzer = ProcessAnalyzer()
        print("ProcessAnalyzer initialized successfully")
        
        for i, log in enumerate(logs):
            print_section(f"Processing Process Log #{i+1}")
            print("Input:")
            pprint(log)
            print()
            
            # Convert to DataFrame as expected by the analyzer
            log_df = pd.DataFrame([log])
            
            print("Analyzing...")
            result = analyzer.analyze(log_df)
            
            print("Result:")
            print_result(result)
            
    except Exception as e:
        print(f"{RED}Error testing process analyzer: {str(e)}{ENDC}")
        import traceback
        traceback.print_exc()

def test_memory_analyzer(logs):
    """Test the memory analyzer with the provided logs"""
    print_header("MEMORY ANALYZER TEST")
    
    try:
        print_section("Initializing MemoryAnalyzer")
        analyzer = MemoryAnalyzer()
        print("MemoryAnalyzer initialized successfully")
        
        for i, log in enumerate(logs):
            print_section(f"Processing Memory Log #{i+1}")
            print("Input:")
            pprint(log)
            print()
            
            # Convert to DataFrame as expected by the analyzer
            log_df = pd.DataFrame([log])
            
            print("Analyzing...")
            result = analyzer.analyze(log_df)
            
            print("Result:")
            print_result(result)
            
    except Exception as e:
        print(f"{RED}Error testing memory analyzer: {str(e)}{ENDC}")
        import traceback
        traceback.print_exc()

def test_disk_analyzer(logs):
    """Test the disk analyzer with the provided logs"""
    print_header("DISK ANALYZER TEST")
    
    try:
        print_section("Initializing DiskAnalyzer")
        analyzer = DiskAnalyzer()
        print("DiskAnalyzer initialized successfully")
        
        for i, log in enumerate(logs):
            print_section(f"Processing Disk Log #{i+1}")
            print("Input:")
            pprint(log)
            print()
            
            # Convert to DataFrame as expected by the analyzer
            log_df = pd.DataFrame([log])
            
            print("Analyzing...")
            result = analyzer.analyze(log_df)
            
            print("Result:")
            print_result(result)
            
    except Exception as e:
        print(f"{RED}Error testing disk analyzer: {str(e)}{ENDC}")
        import traceback
        traceback.print_exc()

def test_network_analyzer(logs):
    """Test the network analyzer with the provided logs"""
    print_header("NETWORK TRAFFIC ANALYZER TEST")
    
    try:
        print_section("Initializing NetworkTrafficAnalyzer")
        analyzer = NetworkTrafficAnalyzer()
        print("NetworkTrafficAnalyzer initialized successfully")
        
        for i, log in enumerate(logs):
            print_section(f"Processing Network Traffic Log #{i+1}")
            print("Input:")
            pprint(log)
            print()
            
            # Note: Network analyzer might have a different interface
            # Adjust accordingly based on your implementation
            print("Analyzing...")
            result = analyzer.analyze(log)
            
            print("Result:")
            print_result(result)
            
    except Exception as e:
        print(f"{RED}Error testing network analyzer: {str(e)}{ENDC}")
        import traceback
        traceback.print_exc()

# Sample data for each model type - useful for quick testing
SAMPLE_PROCESS_LOGS = [
    {
        "PID": "1234",
        "CMD": "unusual_process",
        "TRUN": "3600",
        "TSLPI": "0",
        "TSLPU": "0",
        "POLI": "0",
        "NICE": "19",
        "PRI": "30",
        "RTPR": "0",
        "CPUNR": "0",
        "Status": "R",
        "EXC": "3600",
        "State": "R",
        "CPU": "98.5"
    },
    {
        "PID": "2345",
        "CMD": "normal_process",
        "TRUN": "120",
        "TSLPI": "5",
        "TSLPU": "5",
        "POLI": "0",
        "NICE": "0",
        "PRI": "20",
        "RTPR": "0",
        "CPUNR": "1",
        "Status": "S",
        "EXC": "100",
        "State": "S",
        "CPU": "2.5"
    }
]

SAMPLE_MEMORY_LOGS = [
    {
        "timestamp": "2023-01-01T12:00:00",
        "total_memory": 16384,
        "used_memory": 15500,
        "free_memory": 884,
        "swap_usage": 2048,
        "buffer_size": 512,
        "page_faults": 1500
    },
    {
        "timestamp": "2023-01-01T12:05:00",
        "total_memory": 16384,
        "used_memory": 8192,
        "free_memory": 8192,
        "swap_usage": 256,
        "buffer_size": 512,
        "page_faults": 50
    }
]

SAMPLE_DISK_LOGS = [
    {
        "timestamp": "2023-01-01T12:00:00",
        "disk": "/dev/sda",
        "read_ops": 15000,
        "write_ops": 20000,
        "read_bytes": 500000000,
        "write_bytes": 800000000,
        "io_time": 5000
    },
    {
        "timestamp": "2023-01-01T12:05:00",
        "disk": "/dev/sda",
        "read_ops": 150,
        "write_ops": 200,
        "read_bytes": 5000000,
        "write_bytes": 8000000,
        "io_time": 50
    }
]

SAMPLE_NETWORK_LOGS = [
    {
        "timestamp": "2023-01-01T12:00:00",
        "source_ip": "192.168.1.100",
        "destination_ip": "203.0.113.1",
        "source_port": 45123,
        "destination_port": 80,
        "protocol": "TCP",
        "bytes_sent": 1024,
        "bytes_received": 8192,
        "connection_time": 5.2
    },
    {
        "timestamp": "2023-01-01T12:00:30",
        "source_ip": "192.168.1.105",
        "destination_ip": "203.0.113.5",
        "source_port": 52341,
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_sent": 512,
        "bytes_received": 1024,
        "connection_time": 2.1
    },
    {
        "timestamp": "2023-01-01T12:01:00",
        "source_ip": "45.33.12.10",
        "destination_ports": [22, 23, 25, 80, 443, 3389],
        "connection_attempts": 152,
        "time_window_minutes": 2
    }
]

def main():
    """Main function to parse arguments and run tests"""
    parser = argparse.ArgumentParser(description="Test SIEM models with JSON log data")
    parser.add_argument("--model", type=str, choices=["process", "memory", "disk", "network", "all"], 
                        default="all", help="Model to test")
    parser.add_argument("--input", type=str, help="Path to JSON log file")
    parser.add_argument("--sample", action="store_true", help="Use sample data for testing")
    args = parser.parse_args()
    
    # Print script information
    print_header("SIEM MODEL TESTER")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testing model(s): {args.model}")
    print()

    # Load or use sample data
    process_logs = None
    memory_logs = None
    disk_logs = None
    network_logs = None
    
    if args.sample:
        print("Using sample data for testing")
        process_logs = SAMPLE_PROCESS_LOGS
        memory_logs = SAMPLE_MEMORY_LOGS
        disk_logs = SAMPLE_DISK_LOGS
        network_logs = SAMPLE_NETWORK_LOGS
    elif args.input:
        print(f"Loading logs from: {args.input}")
        logs = load_json_logs(args.input)
        if logs:
            # Try to automatically detect the log type or parse based on a specific format
            # This is a simple example - you may need to adapt based on your actual JSON structure
            if "model_type" in logs:
                # JSON with explicit model type
                process_logs = logs.get("process", [])
                memory_logs = logs.get("memory", [])
                disk_logs = logs.get("disk", [])
                network_logs = logs.get("network", [])
            else:
                # Try to guess based on keys in the first entry
                first_log = logs[0] if logs and len(logs) > 0 else {}
                if "PID" in first_log and "CMD" in first_log:
                    process_logs = logs
                elif "total_memory" in first_log and "used_memory" in first_log:
                    memory_logs = logs
                elif "read_ops" in first_log and "write_ops" in first_log:
                    disk_logs = logs
                elif "source_ip" in first_log and ("destination_ip" in first_log or "destination_ports" in first_log):
                    network_logs = logs
                else:
                    print(f"{YELLOW}Could not automatically determine log type.{ENDC}")
                    print(f"{YELLOW}Using logs for all model types - some may fail.{ENDC}")
                    process_logs = memory_logs = disk_logs = network_logs = logs
    else:
        print(f"{YELLOW}No input file provided and --sample not specified.{ENDC}")
        print(f"{YELLOW}Using sample data for testing.{ENDC}")
        process_logs = SAMPLE_PROCESS_LOGS
        memory_logs = SAMPLE_MEMORY_LOGS
        disk_logs = SAMPLE_DISK_LOGS
        network_logs = SAMPLE_NETWORK_LOGS
    
    # Run the specified tests
    if args.model == "process" or args.model == "all":
        if process_logs:
            test_process_analyzer(process_logs)
        else:
            print(f"{YELLOW}No process logs available to test.{ENDC}")
    
    if args.model == "memory" or args.model == "all":
        if memory_logs:
            test_memory_analyzer(memory_logs)
        else:
            print(f"{YELLOW}No memory logs available to test.{ENDC}")
    
    if args.model == "disk" or args.model == "all":
        if disk_logs:
            test_disk_analyzer(disk_logs)
        else:
            print(f"{YELLOW}No disk logs available to test.{ENDC}")
    
    if args.model == "network" or args.model == "all":
        if network_logs:
            test_network_analyzer(network_logs)
        else:
            print(f"{YELLOW}No network logs available to test.{ENDC}")
    
    print_header("TESTING COMPLETE")

if __name__ == "__main__":
    main()
