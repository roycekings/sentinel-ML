# from app.repositories.logs_repository import LogsRepository
from app.repositories.anomalie_repository import AnomalieRepository
from app.repositories.reported_anomalie import ReportedAnomalieRepository
from app.repositories.alert_reciever import AlertRecieverRepository
from app.schema.anomalie_schema import CreateAnomalieDto 
import traceback
class Anomalie_service:
    def __init__(self):
        self.repository = AnomalieRepository()
        self.reported_anomalie_repository = ReportedAnomalieRepository()
        self.alert_reciever_repository = AlertRecieverRepository()

    async def create_anomalie(self, anomalie: AnomalieRepository):
        print("Creating anomaly:", anomalie)
        return await self.repository.create(anomalie)
 
    async def create_reported_anomalie(self, reported_anomalie: ReportedAnomalieRepository):
        print("Creating reported anomaly:", reported_anomalie)
        return await self.reported_anomalie_repository.create(reported_anomalie)

    async def getAlertReceiver(self):
       try:
            print("Début getAlertReceiver")
            receivers = await self.alert_reciever_repository.getByAutoSend()
            return receivers
       except Exception as e:
           print("Error in getAlertReceiver:", e)
           traceback.print_exc()
           return None
           