
from fastapi import FastAPI, WebSocket
from contextlib import asynccontextmanager
from app.ws.websocket_router import websocket_endpoint
import threading
from app.services.log_poller import init_processors, consumes_logs
from app.services.log_buffer import broadcast_logs_every_5s
import asyncio

main_loop = None
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    print("🚀 Application SentinelAI démarre...")

    await init_processors()
    main_loop = asyncio.get_event_loop()
    def run_consumer():
        try:
            print("🧵 Thread de consommation lancé")
            consumes_logs(main_loop)
        except Exception as e:
            print(f"❌ Erreur dans consumes_logs : {e}")

    threading.Thread(target=run_consumer, daemon=True).start()
    asyncio.create_task(broadcast_logs_every_5s())

    yield  # 👈 Point entre démarrage et arrêt de l'app

    print("🛑 Application SentinelAI en arrêt...")

app = FastAPI(
    title="Sentinel - IA Services",
    version="0.1.0",
    lifespan=lifespan
)

@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    await websocket_endpoint(websocket)

@app.get('/')
async def root():
    return {"test": "ok"}