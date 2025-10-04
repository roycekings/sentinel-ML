from app.db.mongo import mongo_client
from app.schema.anomalie_schema import CreateReportedAnomalieDto
import traceback
import logging
class ReportedAnomalieRepository:
    def __init__(self):
        self.collection =  mongo_client.db['reported_anomalies']
    
    async def create(self, reported_anomalie: CreateReportedAnomalieDto):

        try:
            result = await self.collection.insert_one(reported_anomalie)
            return str(result.inserted_id)
        except Exception as e:
            traceback.print_exc()
            logging.error(f"Failed to connect to MongoDB: {e}")
            raise  # Arrête l'application si la DB est indisponible