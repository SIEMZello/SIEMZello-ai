import os
import sys

# Add the project root to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from memory_models.memory_analyzer import MemoryAnalyzer, generate_sample_data

def test_memory_pipeline():
    # Initialize the analyzer
    print("1. Initializing Memory Analyzer...")
    analyzer = MemoryAnalyzer()
    
    # Generate sample data
    print("\n2. Generating sample memory data...")
    num_samples = 10
    memory_data = generate_sample_data(num_samples)
    print(f"Generated {num_samples} sample records:")
    print(memory_data.head())
    
    # Analyze the data
    print("\n3. Running memory analysis...")
    results = analyzer.analyze(memory_data)
    
    # Print analysis results
    print("\n4. Analysis Results:")
    anomaly_count = sum(1 for r in results if r['is_anomaly'])
    print(f"Total records analyzed: {len(results)}")
    print(f"Anomalies detected: {anomaly_count}")
    
    # Print detailed results for anomalies
    print("\nDetailed anomaly information:")
    for result in results:
        if result['is_anomaly']:
            print(f"\nRecord ID: {result['record_id']}")
            print(f"Timestamp: {result['ts']}")
            print(f"Command: {result['CMD']}")
            print(f"Disk Read: {result['RDDSK']}")
            print(f"Disk Write: {result['WRDSK']}")
            print(f"Disk Usage: {result['DSK']}")
            print(f"Anomaly Probability: {result['anomaly_probability']:.2f}")
    
    # Export results to file
    output_file = "memory_analysis_results.json"
    print(f"\n5. Exporting results to {output_file}...")
    analyzer.export_results(results, filename=output_file)

if __name__ == "__main__":
    test_memory_pipeline()