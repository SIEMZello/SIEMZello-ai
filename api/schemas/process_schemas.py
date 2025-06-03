from pydantic import BaseModel
from typing import Optional

class ProcessLogEntry(BaseModel):
    ts: int
    CMD: str
    TRUN: float  # Changed to float to handle decimal values
    EXC: int
    CPU: float
    NICE: int
    PRI: int
    CPUNR: int
    POLI: str
    Status: str
    State: str
    # Optional fields that may or may not be present
    TSLPI: Optional[int] = None
    TSLPU: Optional[int] = None
    PID: Optional[int] = None
    UID: Optional[int] = None
    USER: Optional[str] = None

class ProcessAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[int]
    CMD: Optional[str]
    TRUN: Optional[float]  # Changed to float
    TSLPI: Optional[int]
    TSLPU: Optional[int]
    EXC: Optional[int]
    CPU: Optional[float]
    NICE: Optional[int]
    PRI: Optional[int]
    CPUNR: Optional[int]
    POLI: Optional[str]
    Status: Optional[str]
    State: Optional[str]
    PID: Optional[int]
    UID: Optional[int]
    USER: Optional[str]
