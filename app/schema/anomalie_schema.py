
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