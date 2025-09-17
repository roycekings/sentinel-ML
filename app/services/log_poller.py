import traceback
# from app.db.mongo import logs_collections
from typing import List, Dict
from app.services.accesslog_anomaly import AccessLogProcessor
# from app.services.authlog_anomaly import AuthLogProcessor
from app.services.syslog_anomaly import LogProcessor
from app.services.tcpdump_anomaly import NetworkLogProcessor
# from app.services.kernlog_anomaly import KernLogProcessor
from app.ws.websocket_router import broadcast_log_count
from app.processors.syslog import SyslogProcessor
from app.processors.auth import AuthLogProcessor
from app.processors.kern import KernLogProcessor
import logging
import asyncio
import pika  # Assurez-vous d'avoir installé pika pour RabbitMQ
import time
import json
from app.services.log_service import Anomalie_service
from datetime import datetime
from collections import defaultdict
from app.services.log_buffer import add_log_to_buffer

logger = logging.getLogger(__name__)
logs_services = Anomalie_service()
log_counter = defaultdict(int)
syspr = SyslogProcessor()
authpr = AuthLogProcessor()
kernpr = KernLogProcessor()

async def init_processors():
    """Initialise les processeurs d'anomalies pour chaque type de log."""
    print("🔄 Initialisation des processeurs d'anomalies...")
    access_processor = AccessLogProcessor()
    # auth_processor = AuthLogProcessor()
    syslog_processor = LogProcessor()
    network_processor = NetworkLogProcessor()
    # kernlog_processor = KernLogProcessor()
    print("✅ Processeurs d'anomalies initialisés avec succès.")


    return {
        "access": access_processor,
        # "auth": auth_processor,
        "syslog": syslog_processor,
        "network": network_processor,
        # "kernlog": kernlog_processor
    }

def consumes_logs(loop):
    logger.info("🔄 Initialisation du consommateur de logs...")
    credentials = pika.PlainCredentials('admin', 'admin')
    parameters = pika.ConnectionParameters('rabbitmq', 5672, '/', credentials)

    max_attempts = 10

    for i in range(max_attempts):
        try:
            logger.info(f"⏳ Tentative de connexion à RabbitMQ ({i+1}/{max_attempts})...")
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue='logs',durable=True)
            logger.info("✅ Connecté à RabbitMQ. En attente de logs...")

            def callback(ch, method, properties, body):
                try:
                    log_data = body.decode('utf-8')
                    
                    # ✅ Tentative de parsing JSON pour MongoDB
                    if isinstance(log_data, str):
                        # timestamp_key = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                        # now = datetime.utcnow()
                        # tierce = now.replace(second=(now.second // 20) * 20, microsecond=0)
                        # timestamp_key = tierce.strftime('%H:%M:%S')
                        timestamp_key = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                        add_log_to_buffer(timestamp_key)
                        log_counter[timestamp_key] += 1
                        # print(log_data)
                        log_data = json.loads(log_data)
                        # print(log_data)
                        # {'deviceId': '6889764128985ee27da61e58', 'typeLog': 'kern', 'rawLog': '2025-07-30T02:49:48.387636+00:00 test kernel: br-1e52ff2ca5dc: port 1(veth59d7c46) entered forwarding state'}}
                        inner_data = log_data.get('data', {})
                        type_log = inner_data.get('typeLog')

                        if type_log == 'syslog':
                            raw_log = inner_data.get('rawLog', '')
                            device_name = inner_data.get('deviceName', '')
                            # print(raw_log)
                            parsed = syspr.parse_log(raw_log)
                            # print(parsed, 5)
                            asyncio.run_coroutine_threadsafe(
                            syspr.detect_attacks([parsed],device_name)
                            , loop
                            )
                        elif type_log == 'kern' :
                            # print(1)
                            raw_log = inner_data.get('rawLog', '')
                            device_name = inner_data.get('deviceName', '')

                            parsed = syspr.parse_log(raw_log)
                            # print(parsed, 5)

                            # asyncio.run_coroutine_threadsafe(
                            #     syspr.detect_attacks([parsed], device_name),
                            #     loop
                            # )
                        elif type_log == "auth":
                            # print(2)
                            raw_log = inner_data.get('rawLog', '')
                            device_name = inner_data.get('deviceName', '')
                            parsed = syspr.parse_log(raw_log)
                            # print(parsed, 5)
                            # asyncio.run_coroutine_threadsafe(
                            #     syspr.detect_attacks([parsed], device_name),
                            #     loop
                            # )


                           

                        # asyncio.run_coroutine_threadsafe(
                        #     broadcast_log_count({
                        #         "timestamp": timestamp_key,
                        #         "count": log_counter[timestamp_key]
                        #     }),
                        #     loop
                        # )

                    # logger.info(f"📥 Nouveau log reçu: {log_data}")
                    
                    # Création de la tâche asynchrone
                    # asyncio.run_coroutine_threadsafe(logs_services.create_log(log_data), loop)
            

                except Exception as e:
                    logger.error(f"❌ Erreur dans la callback RabbitMQ: {type(e).__name__} - {e}")
                    traceback.print_exc()

            channel.basic_consume(queue='logs', on_message_callback=callback, auto_ack=True)
            channel.start_consuming()
            break  # connexion réussie => on sort

        except Exception as e:
            logger.error(f"❌ Erreur tentative {i+1}: {type(e).__name__} - {e}")
            traceback.print_exc()

            if i < max_attempts - 1:
                logger.warning("⚠️ RabbitMQ pas encore prêt. Nouvelle tentative dans 25 secondes...")
                time.sleep(25)
            else:
                logger.critical("🛑 Échec après 10 tentatives. Abandon de la consommation.")



