from pydantic import BaseModel
from typing import List, Optional

class ProcessLogEntry(BaseModel):
    PID: int
    ts: int
    CMD: str
    CPU: float
    MEM: float
    STATUS: str

class ProcessAnalysisRequest(BaseModel):
    logs: List[ProcessLogEntry]

class ProcessAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[str]
    CMD: Optional[str]
    CPU: Optional[float]
    MEM: Optional[float]
    STATUS: Optional[str]

class ProcessAnalysisResponse(BaseModel):
    results: List[ProcessAnalysisResult]
    total_records: int
    anomaly_count: int
