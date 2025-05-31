# Network Traffic Anomaly Detection

A machine learning system for detecting and classifying malicious network traffic.

## Project Overview

This system uses a two-stage machine learning approach:

1. **Detection Model**: Binary classification to identify whether network traffic is normal or malicious
2. **Classification Model**: Multi-class classification to categorize detected attacks into specific attack types

## Repository Structure

```
network_traffic_anomaly_detection/
├── data/                       # Directory for sample data
├── models/                     # Directory for trained models
│   ├── detection_model.cbm     # Binary classification model
│   └── classification_model.cbm # Attack type classification model
├── src/                        # Source code
│   ├── data/                   # Data processing code
│   │   └── preprocessor/       # Data preprocessing code
│   ├── features/               # Feature engineering code
│   └── models/                 # Model implementation code
├── tests/                      # Test scripts
├── copy_models.py              # Script to copy models
├── setup_directory.py          # Script to set up directory structure
├── test_models.py              # Script to test models
├── usage_example.py            # Example usage
└── README.md                   # This file
```

## Quick Start

```python
from src.models.detection_model import DetectionModel
from src.models.classification_model import ClassificationModel
import pandas as pd

# Load your network traffic data
traffic_data = pd.read_csv('your_traffic_data.csv')

# Initialize models
detection_model = DetectionModel()
classification_model = ClassificationModel()

# Stage 1: Binary detection (normal vs. attack)
is_attack = detection_model.predict(traffic_data)
attack_probabilities = detection_model.predict_proba(traffic_data)

# Stage 2: Classification of attack types (only for detected attacks)
attack_indices = [i for i, flag in enumerate(is_attack) if flag]
if attack_indices:
    attack_data = traffic_data.iloc[attack_indices]
    attack_types = classification_model.predict(attack_data)
    attack_type_probabilities = classification_model.predict_proba(attack_data)
```

## Setup Instructions

1. Create the directory structure:
   ```
   python setup_directory.py
   ```

2. Copy the model files:
   ```
   python copy_models.py
   ```

3. Test that everything works:
   ```
   python test_models.py
   ```

4. Run the example:
   ```
   python usage_example.py
   ```

## Required Features

The models expect network traffic data with features including:

- `dur`: Duration of the connection
- `proto`: Protocol type (e.g., tcp, udp, icmp)
- `service`: Service type (e.g., http, ftp, ssh)
- `state`: Connection state
- `spkts`, `dpkts`: Source/destination packet count
- `sbytes`, `dbytes`: Source/destination bytes
- And others (see documentation)

## Model Performance

The detection model achieves high recall (>94%) to minimize missed attacks, while the classification model provides detailed categorization of detected attacks with over 84% F1-score.
