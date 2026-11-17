"""Small connector for the EventSender calls already in your controller."""
import json
from queue import Full
from datetime import datetime, timezone
from os_ken.lib import hub


class EventSender:
    def __init__(self, logger):
        self.logger = logger
        self.pending = hub.Queue(256)
        hub.spawn(self.worker)

    def publish(self, event, **fields):
        record = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
                  "event": event, **fields}
        # A bounded queue prevents a logger outage spawning unlimited workers.
        try:
            self.pending.put_nowait(record)
        except Full:
            self.logger.warning("Logging queue full; event dropped: %s", event)

    def worker(self):
        while True:
            self.send(self.pending.get())

    def send(self, record):
        connection = None
        try:
            data = json.dumps(record, ensure_ascii=False).encode("utf-8")
            if len(data) > 8192:
                raise ValueError("Event exceeds 8192 bytes")
            connection = hub.StreamClient(("127.0.0.1", 9000), timeout=1).connect()
            if connection is None:
                raise OSError("Cannot connect to logging server")
            connection.settimeout(1)
            connection.sendall(data + b"\n")
            with connection.makefile("rb") as reader:
                if reader.readline(64) != b"OK\n":
                    raise OSError("Logger did not acknowledge the event")
        except (OSError, ValueError) as error:
            self.logger.warning("Event not confirmed by logger: %s", error)
        finally:
            if connection is not None:
                connection.close()
