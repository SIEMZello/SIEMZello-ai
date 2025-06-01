# SIEMZello-ai: Intelligent SIEM Threat Detection with Explainable AI

This repository contains a comprehensive set of machine learning models for detecting anomalies in different types of Linux system logs as part of a Security Information and Event Management (SIEM) system. It includes an LLM-based explanation engine that provides human-readable interpretations of detected anomalies.

## Overview

The system consists of four separate machine learning models, each specializing in a different type of log data:

1. **Process Models**: Detect anomalies in Linux process logs (CPU, runtime, etc.)
2. **Memory Models**: Detect anomalies in memory usage logs
3. **Disk Models**: Detect anomalies in disk activity logs
4. **Network Traffic Models**: Detect and classify anomalies in network traffic

Each model has been trained on relevant data and packaged in a modular way that allows for easy integration into a larger SIEM backend.

## Features

- **ML-based Anomaly Detection**: Advanced algorithms to detect security threats
- **Modular Architecture**: Independent modules for different log types
- **Two-Stage Network Analysis**: Detection followed by attack classification
- **Explainable AI**: LLM-based explanations of detected anomalies
- **Severity Assessment**: Classification of threat levels
- **Integrated Analysis**: Correlation of anomalies across different systems

## Directory Structure

```
SIEMzello/
├── process_models/           # Process log anomaly detection
│   ├── models/               # Trained model files
│   ├── src/                  # Source code
│   └── process_analyzer.py   # Main analyzer interface
├── memory_models/            # Memory log anomaly detection
│   ├── models/               # Trained model files
│   ├── src/                  # Source code
│   └── memory_analyzer.py    # Main analyzer interface
├── disk_models/              # Disk activity anomaly detection
│   ├── models/               # Trained model files
│   ├── src/                  # Source code
│   └── disk_analyzer.py      # Main analyzer interface
├── network_traffic_models/   # Network traffic anomaly detection
│   ├── models/               # Trained model files
│   ├── src/                  # Source code
│   └── network_traffic_analyzer.py  # Main analyzer interface
├── explanation_engine.py     # LLM-based anomaly explanation engine
├── templates/                # Templates for generating explanations
├── siem_intelligent_analysis.py  # Demo of models with explanations
├── siem_pipeline_test.py     # Test script for all models
└── api.py                    # FastAPI endpoints for backend integration
```

## Usage

### Requirements

```
numpy>=1.19.0
pandas>=1.0.0
scikit-learn>=0.23.0
xgboost>=1.3.0
catboost>=0.24.0
joblib>=1.0.0
requests>=2.25.0
flask>=2.0.0  # For REST API integration
python-dotenv>=0.15.0  # For environment variable management
```

### Basic Usage

Each log type has a dedicated analyzer class that provides a simple interface:

```python
# Import the appropriate analyzer
from process_models.process_analyzer import ProcessAnalyzer

# Initialize the analyzer
analyzer = ProcessAnalyzer()

# Analyze data
results = analyzer.analyze(log_data)

# Process results
for result in results:
    if result["is_anomaly"]:
        print(f"Anomaly detected: {result}")
```

### With Explanations

```python
from process_models.process_analyzer import ProcessAnalyzer
from explanation_engine import ExplanationEngine

# Initialize analyzers
process_analyzer = ProcessAnalyzer()
explanation_engine = ExplanationEngine()

# Analyze data
results = process_analyzer.analyze(process_data)

# Add explanations to anomalies
for i, result in enumerate(results):
    if result["is_anomaly"]:
        raw_data = process_data.iloc[i].to_dict()
        explained_result = explanation_engine.explain_anomaly("process", result, raw_data)
        print(f"Explained anomaly: {explained_result}")
```

## Input Data Requirements

### Process Model Input Fields

| Field  | Description | Required |
|--------|-------------|----------|
| PID    | Process ID | No |
| ts     | Timestamp | Yes |
| CMD    | Command name | No |
| TRUN   | Total runtime | Yes |
| TSLPI  | Total sleep time (interruptible) | Yes |
| TSLPU  | Total sleep time (uninterruptible) | Yes |
| POLI   | Process scheduling policy | Yes |
| NICE   | Process nice value | Yes |
| PRI    | Process priority | Yes |
| CPUNR  | CPU number | Yes |
| Status | Process status | Yes |
| EXC    | Execution time | Yes |
| State  | Process state | Yes |
| CPU    | CPU usage percentage | Yes |

### Memory Model Input Fields

| Field  | Description | Required |
|--------|-------------|----------|
| CMD    | Command name | No |
| DSK    | Disk usage percentage | Yes |
| RDDSK  | Read disk | Yes |
| WRDSK  | Write disk | Yes |
| ts     | Timestamp | Yes |

### Disk Model Input Fields

| Field  | Description | Required |
|--------|-------------|----------|
| CMD    | Command name | No |
| DSK    | Disk usage percentage | Yes |
| RDDSK  | Read disk | Yes |
| WRDSK  | Write disk | Yes |
| WCANCL | Write cancellations | Yes |
| ts     | Timestamp | Yes |

### Network Traffic Model Input Fields

The network model requires multiple fields related to network connections. Key fields include:

| Field  | Description | Required |
|--------|-------------|----------|
| dur    | Duration | Yes |
| proto  | Protocol | Yes |
| service| Service type | Yes |
| state  | Connection state | Yes |
| spkts  | Source packets | Yes |
| dpkts  | Destination packets | Yes |
| sbytes | Source bytes | Yes |
| dbytes | Destination bytes | Yes |

See complete field list in the documentation.

## API Integration

The system provides a FastAPI interface for easy integration with backend systems:

```python
# Example API call
import requests
import json

data = {
    "type": "process",
    "data": {
        "PID": "1234",
        "ts": "1603739847",
        "CMD": "suspicious_process",
        "TRUN": "3600",
        "CPU": "95.5",
        # Other process fields...
    }
}

response = requests.post("http://localhost:8000/analyze", json=data)
result = response.json()
```

## Recent Fixes and Enhancements

- Fixed import path issues in network traffic models
- Resolved feature name mismatch in process models
- Added LLM-based explanation engine
- Implemented FastAPI endpoints for backend integration
- Added comprehensive documentation

## License

[MIT License](LICENSE)
