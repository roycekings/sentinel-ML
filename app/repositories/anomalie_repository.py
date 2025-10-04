from app.db.mongo import mongo_client
from app.schema.anomalie_schema import CreateAnomalieDto
import logging
import traceback

class AnomalieRepository:
    def __init__(self):
        
        self.collection = mongo_client.db['anomalies']

    async def create (self, anomalie: CreateAnomalieDto):
        try:
            result = await self.collection.insert_one(anomalie)
            return str (result.inserted_id)
        except Exception as e:
                traceback.print_exc()
                logging.error(f"Failed to connect to MongoDB: {e}")
                raise  # Arrête l'application si la DB est indisponible
            

