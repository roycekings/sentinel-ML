from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import logging
load_dotenv ()

class MongoClient:

    def __init__(self):
        try:
            self.client = AsyncIOMotorClient(os.getenv("MONGODB_URI"))
            self.db = self.client[os.getenv("DB_NAME")]
        except Exception as e:
                logging.error(f"Failed to connect to MongoDB: {e}")
                raise  # Arrête l'application si la DB est indisponible
mongo_client = MongoClient ()