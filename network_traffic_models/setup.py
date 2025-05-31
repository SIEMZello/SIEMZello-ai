from setuptools import setup, find_packages

setup(
    name="network_traffic_anomaly_detection",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.20.0",
        "pandas>=1.3.0",
        "scikit-learn>=0.24.0",
        "catboost>=0.26.0",
        "matplotlib>=3.4.0",
        "seaborn>=0.11.0",
        "pyarrow>=4.0.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A machine learning system for detecting and classifying malicious network traffic",
    keywords="network, security, anomaly detection, machine learning",
    python_requires=">=3.7",
)
