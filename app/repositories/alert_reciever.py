from app.db.mongo import mongo_client
import logging
import traceback


# class AlertRecieverRepository:
#     def __init__(self):
#         self.db = mongo_client.db
#         self.collection_name = 'alertreceivers'
#         self.collection = self.db[self.collection_name]

#     async def _collection_exists(self) -> bool:
#         """
#         Vérifie si la collection existe dans la base MongoDB.
#         """
#         try:
#             collections = await self.db.list_collection_names()
#             return self.collection_name in collections
#         except Exception as e:
#             logging.error(f"Erreur lors de la vérification de la collection MongoDB: {e}")
#             return False

#     async def getByAutoSend(self):
#         """
#         Récupère tous les receivers dont autoSend = True, 
#         si la collection existe.
#         """
#         try:
#             exists = await self._collection_exists()
#             if not exists:
#                 logging.warning(f"La collection '{self.collection_name}' n'existe pas.")
#                 return []
#             logging.info(f"Récupération des alert receivers avec autoSend = True depuis la collection '{self.collection_name}'")
#             cursor = self.collection.find({"autoSend": True})
#             alert_receivers = await cursor.to_list(length=None)
#             return alert_receivers

#         except Exception as e:
#             traceback.print_exc()
#             logging.error(f"Erreur MongoDB dans getByAutoSend: {e}")
#             raise
class AlertRecieverRepository:
    def __init__(self):
        self.collection = mongo_client.db['alertreceivers']

    async def getByAutoSend(self):
        try:
            # Vérifie si la collection existe
            collections = await mongo_client.db.list_collection_names()
            if 'alertreceivers' not in collections:
                print("⚠️ Collection absente")
                return []

            cursor = self.collection.find({"autoSend": True})
            alert_receivers = await cursor.to_list(length=None)
            return alert_receivers

        except Exception as e:
            import traceback
            traceback.print_exc()
            import logging
            logging.error(f"Erreur MongoDB: {e}")
            return []
