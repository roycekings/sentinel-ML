
from pydantic import BaseModel
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId

class CreateAnomalieDto(BaseModel):
    timestamp: datetime
    host: str
    process: str
    pid: Optional[int] = None
    message: str
    raw: str
    severity: Optional[int] = None
    anomaly_score: float
    is_anomaly: bool
    device_name: str
    
class CreateReportedAnomalieDto(BaseModel):
    type:str
    ip: Optional[str] = None
    host: Optional[str] = None
    log: Optional[str] = None
    count: Optional[int] = None
    target_user: Optional[str] = None
    timestamp: Optional[datetime] = None
    user_tried: Optional[str] = None
    last_process: Optional[str] = None
    source: Optional[str] = None
    device_name: Optional[str] = None