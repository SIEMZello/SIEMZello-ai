from pydantic import BaseModel
from typing import Optional

class DiskLogEntry(BaseModel):
    PID: int
    ts: int
    CMD: str
    disk_reads: float
    disk_writes: float
    disk_read_bytes: float
    disk_write_bytes: float
    disk_utilization: float

class DiskAnalysisResult(BaseModel):
    record_id: int
    is_anomaly: bool
    anomaly_probability: float
    ts: Optional[str]
    CMD: Optional[str]
    disk_reads: Optional[float]
    disk_writes: Optional[float]
    disk_read_bytes: Optional[float]
    disk_write_bytes: Optional[float]
    disk_utilization: Optional[float]
