from pydantic import BaseModel
from typing import Dict, Optional, List

class NetworkTrafficInput(BaseModel):
    dur: float
    proto: str
    service: str
    state: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    rate: int
    sttl: int
    dttl: int
    sload: float
    dload: float
    sloss: int
    dloss: int
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float
    smean: int
    dmean: int

class DetectionResponse(BaseModel):
    is_attack: bool
    attack_probability: float

class ClassificationResponse(BaseModel):
    attack_type: str
    attack_probabilities: Dict[str, float]

class FullAnalysisResponse(BaseModel):
    is_attack: bool
    attack_probability: float
    attack_type: Optional[str] = None
    attack_probabilities: Optional[Dict[str, float]] = None