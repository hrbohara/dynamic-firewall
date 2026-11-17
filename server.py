import socket
import threading
import argparse
from protocol import send_msg, rcv_msg

parser = argparse.ArgumentParser(description='TCP Server setup via python')

parser.add_argument('-H', '--host', default = '127.0.0.1', help = 'Local IP Address of server.')
parser.add_argument('-p', '--port', type = int, default = '5000', help = 'TCP Port of server.')
parser.add_argument('-t', '--timeout', type=float, default=120,
                    help='Client idle timeout in seconds (default: 120).')

args = parser.parse_args()

if not 1 <= args.port <= 65535:
    parser.error("Port must be between 1 and 65535")
if not 0 < args.timeout <= 3600:
    parser.error("Timeout must be greater than 0 and at most 3600 seconds")

host = args.host
port = args.port

def handle_client(connection, addr):
    with connection:
        connection.settimeout(args.timeout)
        print(f"Connected: {addr}")
        buffer = b""

        try:
            while True:
                msg, buffer = rcv_msg(connection, buffer)

                if msg is None:
                    break

                print(f"Received from {addr}: {msg!r}")
                send_msg(connection, msg)

        except socket.timeout:
            print(f"Client {addr} timed out waiting on socket I/O")

        except (OSError, ValueError) as error:
            print(f"Connection error with {addr}: {error}")

    print(f"Client {addr} disconnected")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()

        print(f"Listening on {host}:{port}")

        while True:
            connection, addr = server.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(connection, addr),
                daemon=True,
            )
            client_thread.start()

except KeyboardInterrupt:
    print("\nServer stopped.")

except OSError as error:
    print(f"Server error: {error}")
