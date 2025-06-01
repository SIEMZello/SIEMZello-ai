#!/usr/bin/env python
"""
SIEM Report Generator

This script demonstrates the complete pipeline:
1. Takes dummy log data for process, memory, disk, and network
2. Passes them through the respective analyzers
3. Sends the results to HuggingFace-based LLM for interpretation
4. Generates a consolidated security report
"""

import os
import sys
import json
import time
import requests
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import the analyzers from their respective modules
try:
    from process_models.process_analyzer import ProcessAnalyzer
    from memory_models.memory_analyzer import MemoryAnalyzer
    from disk_models.disk_analyzer import DiskAnalyzer
    from network_traffic_models.network_traffic_analyzer import NetworkTrafficAnalyzer
except ImportError as e:
    print(f"Error importing analyzers: {e}")
    print("Make sure all model directories are in your Python path")
    sys.exit(1)

class SIEMReportGenerator:
    """
    A class that connects SIEM anomaly detection models with LLM-based explanations
    to generate comprehensive security reports.
    """
    
    def __init__(self, llm_api_key: Optional[str] = None, model_name: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            llm_api_key (str, optional): API key for the HuggingFace service
            model_name (str, optional): The model name to use for explanations
        """
        # Use environment variables if not provided directly
        self.api_key = llm_api_key or os.environ.get("HF_API_KEY", "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")
        
        # Use models that were confirmed to work in testing
        self.model_name = model_name or "HuggingFaceH4/zephyr-7b-beta"
        self.fallback_model = "facebook/bart-large-cnn"
        
        self.api_url = f"https://api-inference.huggingface.co/models/{self.model_name}"
        
        # Initialize analyzers
        self.process_analyzer = None
        self.memory_analyzer = None
        self.disk_analyzer = None
        self.network_analyzer = None
        
        # Load templates for LLM prompting
        self.templates = self._load_templates()
        
        # Initialize analyzers
        self._init_analyzers()
    
    def _init_analyzers(self):
        """Initialize all the SIEM analyzers"""
        try:
            print("Initializing process analyzer...")
            self.process_analyzer = ProcessAnalyzer()
            
            print("Initializing memory analyzer...")
            self.memory_analyzer = MemoryAnalyzer()
            
            print("Initializing disk analyzer...")
            self.disk_analyzer = DiskAnalyzer()
            
            print("Initializing network traffic analyzer...")
            self.network_analyzer = NetworkTrafficAnalyzer()
            
            print("All analyzers initialized successfully")
        except Exception as e:
            print(f"Error initializing analyzers: {e}")
            print("Will attempt to continue with available analyzers")
    
    def _load_templates(self) -> Dict[str, str]:
        """Load explanation templates for each model type"""
        templates = {}
        template_types = ["process", "memory", "disk", "network", "integrated"]
        
        for template_type in template_types:
            template_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 
                "templates", 
                f"{template_type}_explanation_template.txt"
            )
            
            try:
                with open(template_path, "r") as f:
                    templates[template_type] = f.read()
            except FileNotFoundError:
                # Create basic template if file not found
                templates[template_type] = (
                    f"You are a security analyst. Analyze this {template_type} anomaly:\n\n"
                    "Data: {detection_result}\n\n"
                    "Provide a detailed security analysis of what this means, potential threats, "
                    "and recommended actions."
                )
        
        return templates
    
    def query_llm(self, prompt: str, max_retries: int = 3) -> str:
        """
        Query the Hugging Face LLM with improved error handling
        and response processing.
        
        Args:
            prompt (str): The prompt to send to the LLM
            max_retries (int): Number of times to retry on failure
            
        Returns:
            str: The generated text response
        """
        if not self.api_key:
            return "Error: API key not configured"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Create a payload with parameters optimized for security analysis
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 300,
                "temperature": 0.7,
                "top_p": 0.9,
                "do_sample": True,
                "return_full_text": False  # Prevent returning the prompt
            }
        }
        
        # Try the primary model
        response_text = self._try_model_query(
            self.api_url, headers, payload, max_retries, is_fallback=False
        )
        
        # If primary model fails, try the fallback model
        if response_text.startswith("Error:"):
            print(f"Primary model failed. Trying fallback model: {self.fallback_model}")
            fallback_url = f"https://api-inference.huggingface.co/models/{self.fallback_model}"
            response_text = self._try_model_query(
                fallback_url, headers, payload, max_retries, is_fallback=True
            )
        
        return response_text
    
    def _try_model_query(self, api_url, headers, payload, max_retries, is_fallback=False):
        """Helper function to try querying a specific model with retries"""
        for attempt in range(max_retries):
            try:
                model_name = self.fallback_model if is_fallback else self.model_name
                print(f"Querying {model_name}, attempt {attempt + 1}/{max_retries}...")
                
                # Make the request with timeout
                response = requests.post(api_url, headers=headers, json=payload, timeout=30)
                
                # Handle model loading status
                if response.status_code == 503 and "loading" in response.text.lower():
                    wait_time = (attempt + 1) * 2  # Exponential backoff
                    print(f"Model is loading. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                
                # Handle other HTTP errors
                response.raise_for_status()
                
                # Get the result and process based on type
                result = response.json()
                
                # Handle different response formats
                if isinstance(result, list) and len(result) > 0:
                    # Handle summarization models like BART
                    if isinstance(result[0], dict) and "summary_text" in result[0]:
                        return result[0]["summary_text"]
                    # Handle generative models
                    if isinstance(result[0], dict) and "generated_text" in result[0]:
                        return result[0]["generated_text"]
                
                # Handle standard generative models
                if isinstance(result, dict) and "generated_text" in result:
                    return result["generated_text"]
                
                # Return as string if we can't extract in expected format
                return str(result)
                
            except requests.exceptions.HTTPError as e:
                print(f"HTTP Error: {e}")
                if attempt == max_retries - 1:
                    return f"Error: Failed after {max_retries} attempts. {str(e)}"
                time.sleep(2)
                
            except Exception as e:
                print(f"Error: {e}")
                if attempt == max_retries - 1:
                    return f"Error: Failed after {max_retries} attempts. {str(e)}"
                time.sleep(2)
        
        return "Error: Failed to get a response"
    
    def analyze_process_logs(self, process_logs: List[Dict]) -> List[Dict]:
        """Analyze process logs for anomalies"""
        if not self.process_analyzer:
            return [{"error": "Process analyzer not initialized"}]
        
        results = []
        for log in process_logs:
            try:
                # Convert to DataFrame as expected by the analyzer
                log_df = pd.DataFrame([log])
                anomaly_result = self.process_analyzer.analyze(log_df)
                
                # Add the raw data for context
                if isinstance(anomaly_result, dict):
                    anomaly_result["raw_data"] = log
                
                results.append(anomaly_result)
            except Exception as e:
                results.append({
                    "error": f"Failed to analyze process log: {str(e)}",
                    "raw_data": log
                })
        
        return results
    
    def analyze_memory_logs(self, memory_logs: List[Dict]) -> List[Dict]:
        """Analyze memory logs for anomalies"""
        if not self.memory_analyzer:
            return [{"error": "Memory analyzer not initialized"}]
        
        results = []
        for log in memory_logs:
            try:
                # Convert to DataFrame as expected by the analyzer
                log_df = pd.DataFrame([log])
                anomaly_result = self.memory_analyzer.analyze(log_df)
                
                # Add the raw data for context
                if isinstance(anomaly_result, dict):
                    anomaly_result["raw_data"] = log
                
                results.append(anomaly_result)
            except Exception as e:
                results.append({
                    "error": f"Failed to analyze memory log: {str(e)}",
                    "raw_data": log
                })
        
        return results
    
    def analyze_disk_logs(self, disk_logs: List[Dict]) -> List[Dict]:
        """Analyze disk logs for anomalies"""
        if not self.disk_analyzer:
            return [{"error": "Disk analyzer not initialized"}]
        
        results = []
        for log in disk_logs:
            try:
                # Convert to DataFrame as expected by the analyzer
                log_df = pd.DataFrame([log])
                anomaly_result = self.disk_analyzer.analyze(log_df)
                
                # Add the raw data for context
                if isinstance(anomaly_result, dict):
                    anomaly_result["raw_data"] = log
                
                results.append(anomaly_result)
            except Exception as e:
                results.append({
                    "error": f"Failed to analyze disk log: {str(e)}",
                    "raw_data": log
                })
        
        return results
    
    def analyze_network_logs(self, network_logs: List[Dict]) -> List[Dict]:
        """Analyze network traffic logs for attacks"""
        if not self.network_analyzer:
            return [{"error": "Network analyzer not initialized"}]
        
        results = []
        for log in network_logs:
            try:
                # Network analyzer might expect different format
                # Adjust as needed based on your implementation
                attack_result = self.network_analyzer.analyze(log)
                
                # Add the raw data for context
                if isinstance(attack_result, dict):
                    attack_result["raw_data"] = log
                
                results.append(attack_result)
            except Exception as e:
                results.append({
                    "error": f"Failed to analyze network log: {str(e)}",
                    "raw_data": log
                })
        
        return results
    
    def explain_result(self, model_type: str, result: Dict[str, Any]) -> str:
        """
        Generate an explanation for a detection result using the LLM.
        
        Args:
            model_type (str): Type of model ('process', 'memory', 'disk', 'network')
            result (dict): The detection result with raw data
            
        Returns:
            str: LLM-generated explanation
        """
        # Get the template for this model type
        template = self.templates.get(model_type, self.templates.get("integrated"))
        
        # Extract raw data if available
        raw_data = result.get("raw_data", {})
        
        # Remove raw_data from result to avoid duplication
        result_copy = result.copy()
        if "raw_data" in result_copy:
            del result_copy["raw_data"]
        
        # Format the template with the result and raw data
        context = {
            "model_type": model_type,
            "detection_result": json.dumps(result_copy, indent=2),
            "raw_data": json.dumps(raw_data, indent=2),
        }
        
        # Add probability based on model type
        if model_type == "network":
            context["probability"] = result.get("attack_probability", 0)
        else:
            context["probability"] = result.get("anomaly_probability", 0)
        
        # Create the prompt
        try:
            prompt = template.format(**context)
        except KeyError:
            prompt = f"Analyze this {model_type} security event:\n\n{json.dumps(result_copy, indent=2)}"
        
        # Get explanation from LLM
        explanation = self.query_llm(prompt)
        
        return explanation
    
    def generate_integrated_report(self, 
                                  process_results: List[Dict],
                                  memory_results: List[Dict],
                                  disk_results: List[Dict],
                                  network_results: List[Dict]) -> Dict:
        """
        Generate an integrated security report from all analyzers.
        
        Args:
            process_results: Results from process analyzer
            memory_results: Results from memory analyzer
            disk_results: Results from disk analyzer
            network_results: Results from network analyzer
            
        Returns:
            dict: Integrated report with LLM-generated explanation
        """
        # Count anomalies by type
        process_anomalies = sum(1 for r in process_results if r.get("is_anomaly", False))
        memory_anomalies = sum(1 for r in memory_results if r.get("is_anomaly", False))
        disk_anomalies = sum(1 for r in disk_results if r.get("is_anomaly", False))
        network_attacks = sum(1 for r in network_results if r.get("is_attack", False))
        
        total_anomalies = process_anomalies + memory_anomalies + disk_anomalies + network_attacks
        total_records = len(process_results) + len(memory_results) + len(disk_results) + len(network_results)
        
        # Create report structure
        report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_records_analyzed": total_records,
            "total_anomalies_detected": total_anomalies,
            "anomalies_by_type": {
                "process": process_anomalies,
                "memory": memory_anomalies,
                "disk": disk_anomalies,
                "network": network_attacks
            },
            "anomaly_details": {}
        }
        
        # Add individual explanations for anomalies
        if process_anomalies > 0:
            report["anomaly_details"]["process"] = []
            for result in [r for r in process_results if r.get("is_anomaly", False)]:
                explanation = self.explain_result("process", result)
                report["anomaly_details"]["process"].append({
                    "result": result,
                    "explanation": explanation
                })
                
        if memory_anomalies > 0:
            report["anomaly_details"]["memory"] = []
            for result in [r for r in memory_results if r.get("is_anomaly", False)]:
                explanation = self.explain_result("memory", result)
                report["anomaly_details"]["memory"].append({
                    "result": result,
                    "explanation": explanation
                })
                
        if disk_anomalies > 0:
            report["anomaly_details"]["disk"] = []
            for result in [r for r in disk_results if r.get("is_anomaly", False)]:
                explanation = self.explain_result("disk", result)
                report["anomaly_details"]["disk"].append({
                    "result": result,
                    "explanation": explanation
                })
                
        if network_attacks > 0:
            report["anomaly_details"]["network"] = []
            for result in [r for r in network_results if r.get("is_attack", False)]:
                explanation = self.explain_result("network", result)
                report["anomaly_details"]["network"].append({
                    "result": result,
                    "explanation": explanation
                })
        
        # Generate severity level
        if network_attacks > 0:
            highest_attack_prob = max((r.get("attack_probability", 0) for r in network_results 
                                      if r.get("is_attack", False)), default=0)
            if highest_attack_prob > 0.8:
                report["severity"] = "CRITICAL"
            elif highest_attack_prob > 0.6:
                report["severity"] = "HIGH"
            else:
                report["severity"] = "MEDIUM"
        elif total_anomalies > 0:
            # Calculate based on all anomaly types
            if total_anomalies > 5:
                report["severity"] = "HIGH"
            else:
                report["severity"] = "MEDIUM"
        else:
            report["severity"] = "LOW"
        
        # Generate integrated explanation using LLM
        template = self.templates.get("integrated")
        
        # Create a simplified context for the LLM to analyze
        context = {
            "detection_result": json.dumps({
                "timestamp": report["timestamp"],
                "total_anomalies": total_anomalies,
                "anomalies_by_type": report["anomalies_by_type"],
                "severity": report["severity"]
            }, indent=2)
        }
        
        try:
            prompt = template.format(**context)
            integrated_explanation = self.query_llm(prompt)
            report["integrated_explanation"] = integrated_explanation
        except Exception as e:
            report["integrated_explanation"] = f"Error generating integrated explanation: {str(e)}"
        
        return report
    
    def format_report_output(self, report: Dict) -> str:
        """Format the report for console output"""
        output = []
        
        # Add header
        output.append("\n" + "=" * 80)
        output.append(f"SIEM SECURITY REPORT - {report['timestamp']}")
        output.append("=" * 80 + "\n")
        
        # Add summary
        output.append(f"SEVERITY: {report['severity']}")
        output.append(f"Total records analyzed: {report['total_records_analyzed']}")
        output.append(f"Total anomalies detected: {report['total_anomalies_detected']}")
        output.append("\nAnomalies by type:")
        for type_name, count in report["anomalies_by_type"].items():
            output.append(f"  - {type_name.capitalize()}: {count}")
        
        # Add integrated explanation
        if "integrated_explanation" in report and report["integrated_explanation"]:
            output.append("\n" + "-" * 80)
            output.append("INTEGRATED ANALYSIS")
            output.append("-" * 80)
            output.append(report["integrated_explanation"])
        
        # Add details for each anomaly type
        if report["anomaly_details"]:
            output.append("\n" + "-" * 80)
            output.append("DETAILED ANOMALIES")
            output.append("-" * 80)
            
            for model_type, anomalies in report["anomaly_details"].items():
                if anomalies:
                    output.append(f"\n{model_type.upper()} ANOMALIES:")
                    for i, anomaly in enumerate(anomalies, 1):
                        output.append(f"\n[Anomaly {i}]")
                        if "explanation" in anomaly and anomaly["explanation"]:
                            output.append(anomaly["explanation"])
        
        output.append("\n" + "=" * 80)
        return "\n".join(output)


# Sample data for testing
def get_dummy_process_logs():
    """Generate dummy process logs"""
    return [
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
            "CPU": "98.5",
            "is_anomaly": True,
            "anomaly_probability": 0.85
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
            "CPU": "2.5",
            "is_anomaly": False,
            "anomaly_probability": 0.12
        }
    ]

def get_dummy_memory_logs():
    """Generate dummy memory logs"""
    return [
        {
            "timestamp": "2023-01-01T12:00:00",
            "total_memory": 16384,
            "used_memory": 15500,
            "free_memory": 884,
            "swap_usage": 2048,
            "buffer_size": 512,
            "page_faults": 1500,
            "is_anomaly": True,
            "anomaly_probability": 0.78
        },
        {
            "timestamp": "2023-01-01T12:05:00",
            "total_memory": 16384,
            "used_memory": 8192,
            "free_memory": 8192,
            "swap_usage": 256,
            "buffer_size": 512,
            "page_faults": 50,
            "is_anomaly": False,
            "anomaly_probability": 0.05
        }
    ]

def get_dummy_disk_logs():
    """Generate dummy disk logs"""
    return [
        {
            "timestamp": "2023-01-01T12:00:00",
            "disk": "/dev/sda",
            "read_ops": 15000,
            "write_ops": 20000,
            "read_bytes": 500000000,
            "write_bytes": 800000000,
            "io_time": 5000,
            "is_anomaly": True,
            "anomaly_probability": 0.92
        },
        {
            "timestamp": "2023-01-01T12:05:00",
            "disk": "/dev/sda",
            "read_ops": 150,
            "write_ops": 200,
            "read_bytes": 5000000,
            "write_bytes": 8000000,
            "io_time": 50,
            "is_anomaly": False,
            "anomaly_probability": 0.08
        }
    ]

def get_dummy_network_logs():
    """Generate dummy network logs"""
    return [
        {
            "timestamp": "2023-01-01T12:00:00",
            "source_ip": "192.168.1.100",
            "destination_ip": "203.0.113.1",
            "source_port": 45123,
            "destination_port": 80,
            "protocol": "TCP",
            "bytes_sent": 1024,
            "bytes_received": 8192,
            "connection_time": 5.2,
            "is_attack": True,
            "attack_probability": 0.88,
            "attack_type": "Data Exfiltration"
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
            "connection_time": 2.1,
            "is_attack": False,
            "attack_probability": 0.03
        },
        {
            "timestamp": "2023-01-01T12:01:00",
            "source_ip": "45.33.12.10",
            "destination_ports": [22, 23, 25, 80, 443, 3389],
            "connection_attempts": 152,
            "time_window_minutes": 2,
            "is_attack": True,
            "attack_probability": 0.93,
            "attack_type": "Reconnaissance"
        }
    ]

def main():
    """Main function to test the SIEM report generator with dummy data"""
    print("\nInitializing SIEM Report Generator...")
    generator = SIEMReportGenerator()
    
    print("\nGenerating sample logs...")
    process_logs = get_dummy_process_logs()
    memory_logs = get_dummy_memory_logs()
    disk_logs = get_dummy_disk_logs()
    network_logs = get_dummy_network_logs()
    
    print("\nAnalyzing logs with SIEM models...")
    # For testing purposes, use the dummy logs directly since they already contain analysis results
    # In a real scenario, we would pass these logs to the analyzers
    # process_results = generator.analyze_process_logs(process_logs)
    # memory_results = generator.analyze_memory_logs(memory_logs)
    # disk_results = generator.analyze_disk_logs(disk_logs)
    # network_results = generator.analyze_network_logs(network_logs)
    
    print("\nGenerating integrated security report...")
    report = generator.generate_integrated_report(
        process_logs, memory_logs, disk_logs, network_logs
    )
    
    print("\nFormatting report for output...")
    formatted_report = generator.format_report_output(report)
    
    print(formatted_report)
    
    # Save report to file
    with open("siem_security_report.txt", "w") as f:
        f.write(formatted_report)
    
    print(f"\nReport saved to: {os.path.abspath('siem_security_report.txt')}")

if __name__ == "__main__":
    main()
