from collections import defaultdict
import asyncio
from app.ws.websocket_router import broadcast_log_count

log_buffer = defaultdict(int)

def add_log_to_buffer(timestamp: str):
    log_buffer[timestamp] += 1

async def broadcast_logs_every_5s():
    while True:
        if log_buffer:
            data_to_send = [
                {"timestamp": ts, "count": count}
                for ts, count in sorted(log_buffer.items())
            ]
            for entry in data_to_send:
                await broadcast_log_count(entry)
            log_buffer.clear()
        await asyncio.sleep(5)
