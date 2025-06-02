import requests

# Test prediction
data = {
    "dur": 1.0,
    "proto": "tcp",
    "service": "http",
    "state": "CON",
    "spkts": 10,
    "dpkts": 20,
    "sbytes": 1000,
    "dbytes": 2000,
    "rate": 50,
    "sttl": 64,
    "dttl": 64,
    "sload": 0.5,
    "dload": 0.8,
    "sloss": 0,
    "dloss": 0,
    "sinpkt": 0.1,
    "dinpkt": 0.2,
    "sjit": 0.01,
    "djit": 0.01,
    "smean": 500,
    "dmean": 600
}

response = requests.post("http://127.0.0.1:8000//api/v1/predict", json=data)
print(response.json())