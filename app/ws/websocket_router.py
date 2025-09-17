# from fastapi import WebSocket, WebSocketDisconnect
# from typing import List

# connected_clients: List[WebSocket] = []

# async def broadcast_log_count(data: dict):
#     """Envoie les données à tous les clients connectés"""
#     for ws in connected_clients:
#         await ws.send_json(data)

# async def websocket_endpoint(websocket: WebSocket):
#     await websocket.accept()
#     connected_clients.append(websocket)
#     try:
#         while True:
#             await websocket.receive_text()  # Optionnel (keep alive)
#     except WebSocketDisconnect:
#         connected_clients.remove(websocket)


from fastapi import WebSocket, WebSocketDisconnect
from typing import List

connected_clients: List[WebSocket] = []

async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

async def broadcast_log_count(data: dict):
    for ws in connected_clients:
        try:
            await ws.send_json(data)
        except:
            connected_clients.remove(ws)
