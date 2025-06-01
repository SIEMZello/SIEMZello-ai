# Network Traffic Model Tester

This script demonstrates how to use the network traffic model to analyze JSON log entries. It's designed to be simple and straightforward for testing purposes.

## Usage

```bash
python test_network_model.py
```

The script comes with a pre-configured test log entry. It will:

1. Initialize the network traffic analyzer
2. Analyze the provided log entry
3. Display the analysis results, including:
   - Whether an attack was detected
   - The attack probability percentage
   - The attack type (if detected)
   - Full model output details
4. Save the result to `network_analysis_result.json` for reference

## Testing Your Own Logs

To test your own network logs, simply modify the `log_entry` variable in the script:

```python
log_entry = {
    "dur": 0.007999897003173828,
    "proto": "tcp",
    # ... your log data here ...
}
```

## Batch Processing

The script includes sample code showing how to process multiple logs from a file:

```python
import json
from test_network_model import test_network_log

# Load logs from file
with open('your_logs.json', 'r') as f:
    logs = json.load(f)

# Process each log
results = []
for log in logs:
    result = test_network_log(log, verbose=False)
    results.append(result)
    
# Count attacks
attack_count = sum(1 for r in results if r.get('is_attack', False))
print(f"Processed {len(results)} logs, detected {attack_count} attacks")
```

## Required Fields

The network traffic analyzer expects the following fields in each log entry:

- `dur`: Duration of the connection
- `proto`: Protocol (tcp, udp, etc.)
- `spkts`: Source packets
- `dpkts`: Destination packets
- `sbytes`: Source bytes
- `dbytes`: Destination bytes
- `rate`: Connection rate
- `sttl`: Source TTL
- `dttl`: Destination TTL
- `sload`: Source load
- `dload`: Destination load
- Various other network traffic features

See the sample log in the script for a complete example.

## Output Format

The analysis result is a dictionary containing:
- `is_attack`: Boolean indicating if an attack was detected
- `attack_probability`: Value between 0 and 1 indicating confidence level
- `attack_type`: Type of attack detected (DoS, Exploits, Reconnaissance, etc.)
- Additional details based on the model
