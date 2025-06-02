from pydantic import BaseModel
from typing import List, Optional

class MemoryLogEntry(BaseModel):
    PID: int
    ts: int
    CMD: str
    RDDSK: str
    WRDSK: str
    WCANCL: str
    DSK: str

class MemoryAnalysisRequest(BaseModel):
    logs: List[MemoryLogEntry]

class MemoryAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[str]
    CMD: Optional[str]
    RDDSK: Optional[str]
    WRDSK: Optional[str]
    DSK: Optional[str]

class MemoryAnalysisResponse(BaseModel):
    results: List[MemoryAnalysisResult]
    total_records: int
    anomaly_count: int
