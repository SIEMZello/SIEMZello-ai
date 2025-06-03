from pydantic import BaseModel
from typing import Optional

class DiskLogEntry(BaseModel):
    ts: int
    PID: int
    CMD: str
    RDDSK: str
    WRDSK: str
    WCANCL: str
    DSK: str

class DiskAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[int]
    CMD: Optional[str]
    RDDSK: Optional[str]
    WRDSK: Optional[str]
    WCANCL: Optional[str]
    DSK: Optional[str]
    PID: Optional[int]
