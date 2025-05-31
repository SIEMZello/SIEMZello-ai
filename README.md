# SIEMZello-ai: Intelligent SIEM Threat Detection with Explainable AI

This repository contains a comprehensive set of machine learning models for detecting anomalies in different types of Linux system logs as part of a Security Information and Event Management (SIEM) system. It includes an LLM-based explanation engine that provides human-readable interpretations of detected anomalies.

## Overview

The system consists of four separate machine learning models, each specializing in a different type of log data:

1. **Process Models**: Detect anomalies in Linux process logs
2. **Memory Models**: Detect anomalies in memory usage logs
3. **Disk Models**: Detect anomalies in disk activity logs
4. **Network Traffic Models**: Detect and classify anomalies in network traffic

Each model has been trained on relevant data and packaged in a modular way that allows for easy integration into a larger SIEM backend.

### New! Explainable AI Components

The system now includes an explanation engine that provides:

- Detailed, human-readable explanations for each detected anomaly
- Severity assessments based on anomaly probabilities
- Actionable recommendations for security analysts
- Integrated analysis across different log types
- Correlation of anomalies for holistic security insights

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
├── network_traffic_models/    # Network traffic anomaly detection
│   ├── models/               # Trained model files
│   ├── src/                  # Source code
│   └── network_traffic_analyzer.py  # Main analyzer interface
├── explanation_engine.py     # LLM-based anomaly explanation engine
├── templates/                # Templates for generating explanations
│   ├── process_explanation_template.txt
│   ├── memory_explanation_template.txt
│   ├── disk_explanation_template.txt
│   ├── network_explanation_template.txt
│   └── integrated_explanation_template.txt
├── siem_intelligent_analysis.py  # Demo of models with explanations
├── siem_pipeline_test.py     # Test script for all models
└── network_pipeline_test.py  # Test script for network models
```

## How to Use

### Dependencies

Each model requires the following Python packages:
- numpy
- pandas
- scikit-learn
- xgboost (for process, memory, and disk models)
- catboost (for network models)

### Using the Models

Each log type has a dedicated analyzer class that provides a simple interface for anomaly detection:

## Input Data Requirements

For detailed information about the required input data formats for each model, please refer to the [Input Data Requirements](INPUT_DATA_REQUIREMENTS.md) document. This document provides comprehensive specifications for:

1. Required fields for each model type
2. Data type expectations
3. Sample JSON inputs

## Explainable AI Integration

The system now includes an explanation engine that converts binary model outputs into detailed, human-readable security insights. This component:

1. Takes raw model outputs and input data
2. Generates contextual explanations of detected anomalies
3. Provides severity assessments and recommendations
4. Correlates anomalies across different data sources
5. Creates integrated security analysis

### Using the Explanation Engine

```python
# Initialize the explanation engine
from explanation_engine import ExplanationEngine
explanation_engine = ExplanationEngine()

# Analyze data with a SIEM model
process_analyzer = ProcessAnalyzer()
results = process_analyzer.analyze(process_data)

# Add explanations to anomalies
for i, result in enumerate(results):
    if result["is_anomaly"]:
        raw_data = process_data.iloc[i].to_dict()
        explained_result = explanation_engine.explain_anomaly(
            "process", result, raw_data
        )
        # explained_result now contains:
        # - Original anomaly data
        # - Human-readable explanation
        # - Severity assessment
        # - Recommended actions
```

### REST API Integration

See `siem_intelligent_analysis.py` for an example of how to integrate this system with a REST API for backend use.
4. Special handling for specific fields
5. Preprocessing notes

The backend team should follow these specifications when integrating the models into the SIEM platform.
