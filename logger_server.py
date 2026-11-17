"""Run: python3 logger_server.py. Prints events and appends to security.log."""
import socket
import json
from datetime import datetime, timezone

HOST = "127.0.0.1"
PORT = 9000
LOG_FILE = "security.log"


def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen()
            print(f"Logger listening on {HOST}:{PORT}. Saving to {LOG_FILE}", flush=True)

            while True:
                connection, address = server.accept()
                with connection:
                    connection.settimeout(3)
                    try:
                        # One complete JSON line per connection, at most 8192 bytes.
                        with connection.makefile("rb") as reader:
                            data = reader.readline(8194)
                            if not data:
                                continue
                            if not data.endswith(b"\n") or len(data) > 8193:
                                raise ValueError("Incomplete or oversized event")
                            event = json.loads(data)
                            if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                                raise ValueError("Expected a JSON object with an event name")

                            event["received_at_utc"] = datetime.now(timezone.utc).isoformat()
                            # The reporter is the controller; src/dst describe the traffic.
                            event["reporter_ip"] = address[0]
                            line = json.dumps(event, ensure_ascii=False)
                            with open(LOG_FILE, "a", encoding="utf-8") as log:
                                log.write(line + "\n")
                            print(line, flush=True)
                            connection.sendall(b"OK\n")

                    except (OSError, ValueError) as error:
                        print(f"Logging error: {error}", flush=True)
                        try:
                            connection.sendall(b"ERROR\n")
                        except OSError:
                            pass
    except KeyboardInterrupt:
        print("\nLogger stopped.")
    except OSError as error:
        raise SystemExit(f"Logger error: {error}")


if __name__ == "__main__":
    main()
