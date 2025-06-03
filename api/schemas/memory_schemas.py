from pydantic import BaseModel
from typing import Optional

class MemoryLogEntry(BaseModel):
    PID: int
    ts: int
    CMD: str
    RDDSK: str
    WRDSK: str
    WCANCL: str
    DSK: str

class MemoryAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[str]
    CMD: Optional[str]
    RDDSK: Optional[str]
    WRDSK: Optional[str]
    DSK: Optional[str]
