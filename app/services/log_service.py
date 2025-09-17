# from app.repositories.logs_repository import LogsRepository
from app.repositories.anomalie_repository import AnomalieRepository
from app.schema.anomalie_schema import CreateAnomalieDto 

class Anomalie_service:
    def __init__(self):
        self.repository = AnomalieRepository()

    async def create_anomalie(self, anomalie: AnomalieRepository):
        print("Creating anomaly:", anomalie)
        return await self.repository.create(anomalie)
 