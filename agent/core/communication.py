import asyncio
import json
import logging
import time
import zlib
import threading
from typing import Optional, Callable

import aiohttp
import websocket

logger = logging.getLogger("aegisx.communication")


class CommunicationModule:
    def __init__(self, config: dict, agent_id: str = None):
        self._server_url = config.get("server_url", "").rstrip("/")
        self._registration_key = config.get("registration_key", "")
        self._tenant_id = config.get("tenant_id", "")
        self._agent_id = agent_id

        comm_config = config.get("communication", {})
        self._reconnect_base_delay = comm_config.get("reconnect_base_delay", 5)
        self._reconnect_max_delay = comm_config.get("reconnect_max_delay", 300)
        self._reconnect_max_attempts = comm_config.get("reconnect_max_attempts", 0)
        self._batch_size = comm_config.get("batch_size", 100)
        self._compress_data = comm_config.get("compress_data", True)

        self._session: Optional[aiohttp.ClientSession] = None
        self._ws: Optional[websocket.WebSocketApp] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._ws_connected = False
        self._ws_url = self._server_url.replace("http", "ws") + "/api/v1/agent/ws"

        self._data_queue: list = []
        self._command_callbacks: list[Callable] = []
        self._shutdown_event = threading.Event()
        self._reconnect_event = threading.Event()
        self._registered = False

        self._session_lock = asyncio.Lock()

    @property
    def is_registered(self) -> bool:
        return self._registered

    @property
    def agent_id(self) -> str:
        return self._agent_id

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session is None or self._session.closed:
                connector = aiohttp.TCPConnector(limit=10, force_close=False)
                timeout = aiohttp.ClientTimeout(total=30)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=self._build_headers(),
                )
            return self._session

    def _build_headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Key": self._registration_key,
            "X-Tenant-ID": self._tenant_id,
        }
        if self._agent_id:
            headers["X-Agent-ID"] = self._agent_id
        return headers

    async def register(self, agent_info: dict) -> dict:
        session = await self._get_session()
        url = f"{self._server_url}/api/v1/agent/register"
        payload = {
            "agent_key": self._registration_key,
            "tenant_id": self._tenant_id,
            "hostname": agent_info.get("hostname", ""),
            "platform": agent_info.get("platform", ""),
            "os_info": agent_info.get("os_info", {}),
            "architecture": agent_info.get("architecture", ""),
            "agent_version": agent_info.get("agent_version", "1.0.0"),
            "python_version": agent_info.get("python_version", ""),
            "collectors": agent_info.get("collectors", []),
        }

        for attempt in range(self._reconnect_max_attempts or 10):
            try:
                async with session.post(url, json=payload) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        self._agent_id = data.get("agent_id", self._agent_id)
                        self._registered = True
                        logger.info(f"Agent registered successfully. ID: {self._agent_id}")
                        if self._session and not self._session.closed:
                            self._session.headers.update(self._build_headers())
                        return data
                    else:
                        logger.error(f"Registration failed: {resp.status} - {data}")
                        return {"error": data.get("error", f"HTTP {resp.status}")}
            except aiohttp.ClientError as e:
                logger.warning(f"Registration attempt {attempt + 1} failed: {e}")
            except Exception as e:
                logger.error(f"Registration error: {e}")

            if attempt < self._reconnect_max_attempts - 1 or self._reconnect_max_attempts == 0:
                delay = min(self._reconnect_base_delay * (2 ** attempt), self._reconnect_max_delay)
                await asyncio.sleep(delay)

        return {"error": "Max registration attempts reached"}

    async def heartbeat(self) -> dict:
        if not self._registered or not self._agent_id:
            return {"error": "Agent not registered"}

        session = await self._get_session()
        url = f"{self._server_url}/api/v1/agent/heartbeat"
        payload = {
            "agent_id": self._agent_id,
            "timestamp": int(time.time()),
            "status": "online",
        }

        try:
            async with session.post(url, json=payload) as resp:
                data = await resp.json()
                if resp.status == 410:
                    logger.warning("Agent not recognized, re-registering...")
                    self._registered = False
                return data
        except aiohttp.ClientError as e:
            logger.warning(f"Heartbeat failed: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return {"error": str(e)}

    async def send_data(self, data: dict | list) -> dict:
        if not self._registered or not self._agent_id:
            return {"error": "Agent not registered"}

        payload = {
            "agent_id": self._agent_id,
            "timestamp": int(time.time()),
            "data": data if isinstance(data, list) else [data],
        }

        if self._compress_data and len(json.dumps(payload)) > 1024:
            compressed = zlib.compress(json.dumps(payload).encode())
            payload = {"agent_id": self._agent_id, "compressed": True, "payload": compressed.hex()}

        session = await self._get_session()
        url = f"{self._server_url}/api/v1/agent/data"

        try:
            async with session.post(url, json=payload) as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Data send failed: {e}")
            self._data_queue.append(data)
            return {"error": str(e)}

    def connect_ws(self, on_command: Callable = None):
        if on_command:
            self._command_callbacks.append(on_command)
        self._shutdown_event.clear()
        self._reconnect_event.clear()
        self._ws_thread = threading.Thread(target=self._ws_loop, daemon=True)
        self._ws_thread.start()

    def _ws_loop(self):
        ws_url = f"{self._ws_url}?agent_id={self._agent_id}&key={self._registration_key}"
        attempt = 0

        while not self._shutdown_event.is_set():
            try:
                self._ws = websocket.WebSocketApp(
                    ws_url,
                    on_open=self._on_ws_open,
                    on_message=self._on_ws_message,
                    on_error=self._on_ws_error,
                    on_close=self._on_ws_close,
                )
                self._ws.run_forever(
                    ping_interval=30,
                    ping_timeout=10,
                )
            except Exception as e:
                logger.error(f"WebSocket error: {e}")

            if self._shutdown_event.is_set():
                break

            delay = min(self._reconnect_base_delay * (2 ** attempt), self._reconnect_max_delay)
            attempt += 1
            logger.info(f"WebSocket reconnecting in {delay}s (attempt {attempt})")
            self._shutdown_event.wait(delay)

    def _on_ws_open(self, ws):
        self._ws_connected = True
        logger.info("WebSocket connected")
        self._flush_data_queue()

    def _on_ws_message(self, ws, message):
        try:
            msg = json.loads(message)
            msg_type = msg.get("type", "")

            if msg_type == "command":
                command = msg.get("command", {})
                logger.info(f"Received command: {command.get('action')}")
                for cb in self._command_callbacks:
                    try:
                        cb(command)
                    except Exception as e:
                        logger.error(f"Command callback error: {e}")

            elif msg_type == "config_update":
                pass

            elif msg_type == "collect":
                pass

        except json.JSONDecodeError:
            logger.warning(f"Invalid WS message: {message[:200]}")
        except Exception as e:
            logger.error(f"WS message handling error: {e}")

    def _on_ws_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")

    def _on_ws_close(self, ws, close_status_code, close_msg):
        self._ws_connected = False
        logger.info(f"WebSocket closed: {close_status_code} - {close_msg}")

    def _flush_data_queue(self):
        if self._data_queue:
            logger.info(f"Flushing {len(self._data_queue)} queued data items via WebSocket")
            while self._data_queue:
                item = self._data_queue.pop(0)
                try:
                    self._ws.send(json.dumps(item))
                except Exception as e:
                    logger.error(f"Failed to send queued data: {e}")
                    self._data_queue.insert(0, item)
                    break

    async def shutdown(self):
        self._shutdown_event.set()

        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass

        async with self._session_lock:
            if self._session and not self._session.closed:
                await self._session.close()

        logger.info("Communication module shut down")

    def on_command(self, callback: Callable):
        self._command_callbacks.append(callback)

    async def flush_queue(self):
        if not self._data_queue:
            return

        items = self._data_queue[:self._batch_size]
        self._data_queue = self._data_queue[self._batch_size:]

        await self.send_data(items)
