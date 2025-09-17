from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId

# Support ObjectId
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)
    
    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

# Modèle principal
class AnomalyLog(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
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

    class Config:
        allow_population_by_field_name = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "timestamp": "2025-07-30T09:55:14.997718+00:00",
                "host": "test-server",
                "process": "kernel",
                "pid": None,
                "message": "br-1e52ff2ca5dc: port 1(veth123) entered forwarding state",
                "raw": "2025-07-30T09:55:14.997718+00:00 test kernel: ...",
                "severity": 1,
                "anomaly_score": 0.215,
                "is_anomaly": True,
                "device_name": "srv-nginx-prod"
            }
        }
