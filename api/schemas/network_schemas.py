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
    rate: float
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
    swin: int
    dwin: int
    stcpb: int
    dtcpb: int
    tcprtt: float
    synack: float
    ackdat: float
    smean: float  # Accepts int/float
    dmean: float  # Accepts int/float
    trans_depth: int
    is_sm_ips_ports: bool  # Accepts bool/int (will coerce int 0/1 to bool)
    ct_state_ttl: int
    ct_flw_http_mthd: int
    is_ftp_login: bool  # Accepts bool/int
    ct_ftp_cmd: int
    ct_srv_src: int
    ct_srv_dst: int
    ct_dst_ltm: int
    ct_src_ltm: int
    ct_src_dport_ltm: int
    ct_dst_sport_ltm: int
    ct_src_src_ltm: int

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