import socket
import argparse
import csv
import fcntl
import os
import time
from datetime import datetime, timezone
from protocol import send_msg, rcv_msg

parser = argparse.ArgumentParser(description="Interactive TCP echo client")

parser.add_argument('-H', '--host', default = '127.0.0.1', help = 'Server address to connect to',)
parser.add_argument('-p', '--port', type = int, default = 5000, help = 'Server TCP port',)
parser.add_argument('-t', '--timeout', type = float, default = 5.0, help = 'Socket operation timeout in seconds',)
parser.add_argument('--label', default='dynamic', help='Experiment label, e.g. static or dynamic')
parser.add_argument('--csv', default='client_metrics.csv', help='Append measurements to this CSV file')

args = parser.parse_args()

if not 1 <= args.port <= 65535:
    parser.error("Port must be between 1 and 65535")

if not 0 < args.timeout <= 300:
    parser.error("Timeout must be greater than 0 and at most 300 seconds")

host = args.host
port = args.port
source = ''
operation = None
payload_bytes = 0


def record(status, started, detail=''):
    elapsed = (time.perf_counter() - started) * 1000
    print(f"{operation}: {status} ({elapsed:.3f} ms)")
    try:
        with open(args.csv, 'a', newline='', encoding='utf-8') as output:
            # Mininet hosts share files: lock so concurrent clients do not mix rows.
            fcntl.flock(output, fcntl.LOCK_EX)
            writer = csv.writer(output)
            if os.fstat(output.fileno()).st_size == 0:
                writer.writerow(['timestamp_utc', 'label', 'src', 'dst', 'port',
                                 'operation', 'status', 'elapsed_ms', 'bytes', 'detail'])
            writer.writerow([datetime.now(timezone.utc).isoformat(), args.label,
                             source, host, port, operation, status,
                             f'{elapsed:.3f}', payload_bytes, detail])
            output.flush()
    except OSError as error:
        print(f"Could not save measurement: {error}")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(args.timeout)
        operation = 'connect'
        started = time.perf_counter()
        try:
            client.connect((host, port))
        finally:
            source = client.getsockname()[0]
        record('success', started)
        operation = None

        print("Connected. Type :q to leave.")
        buffer = b""

        while True:
            msg = input("Message: ")

            if msg == ":q":
                break

            payload_bytes = len(msg.encode('utf-8'))
            operation = 'echo'
            started = time.perf_counter()
            send_msg(client, msg)
            reply, buffer = rcv_msg(client, buffer)

            if reply is None:
                record('closed', started, 'Server closed the connection')
                operation = None
                print("Server closed the connection.")
                break

            if reply != msg:
                raise ValueError('Echo did not match the sent message')

            record('success', started)
            print("Server replied:", reply)
            operation = None

except (OSError, ValueError) as error:
    if operation is not None:
        status = 'timeout' if isinstance(error, TimeoutError) else 'error'
        record(status, started, str(error))
    print(f"Client error: {error}")

except (KeyboardInterrupt, EOFError):
    print("\nClient stopped.")
