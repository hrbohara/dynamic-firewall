import socket
import json
import ipaddress


CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 9999


# --------------------------------------------------
# CONNECT TO FIREWALL CONTROLLER
# --------------------------------------------------

def send_request(request):

    client = None
    try:

        client = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        client.settimeout(3)
        client.connect(
            (CONTROLLER_IP, CONTROLLER_PORT)
        )

        client.sendall(
            (json.dumps(request) + "\n").encode()
        )

        response = b""

        while b"\n" not in response:

            chunk = client.recv(4096)

            if not chunk:
                break

            response += chunk
            if len(response) > 65536:
                raise ValueError("Controller response too large")

        client.close()

        if not response:
            print("No response from controller.")
            return None

        return json.loads(
            response.split(b"\n", 1)[0].decode()
        )

    except ConnectionRefusedError:

        print("Could not connect to controller.")
        print("Make sure OS-Ken is running.")

        return None

    except Exception as e:

        print("Error:", e)

        return None

    finally:
        if client is not None:
            client.close()


# --------------------------------------------------
# GET RULE DETAILS
# --------------------------------------------------

def get_rule():

    try:

        src = input("Source IP: ").strip()
        ipaddress.IPv4Address(src)

        dst = input("Destination IP: ").strip()
        ipaddress.IPv4Address(dst)

        dst_port = int(input("Destination TCP port: ").strip())
        if not 1 <= dst_port <= 65535:
            raise ValueError("Invalid port")

        return {
            "src": src,
            "dst": dst,
            "dst_port": dst_port,
            "protocol": "TCP"
        }

    except ValueError:

        print("Enter valid IPv4 addresses and a TCP port from 1 to 65535.")
        return None


# --------------------------------------------------
# ADD RULE
# --------------------------------------------------

def add_rule():

    rule = get_rule()

    if rule is None:
        return

    action = input(
        "Action (BLOCK/ALLOW): "
    ).strip().upper()

    if action not in ["BLOCK", "ALLOW"]:

        print("Invalid action.")
        return

    request = {
        "command": "ADD",
        "src": rule["src"],
        "dst": rule["dst"],
        "dst_port": rule["dst_port"],
        "protocol": "TCP",
        "action": action
    }

    response = send_request(request)

    if response:
        print(response)


# --------------------------------------------------
# REMOVE RULE
# --------------------------------------------------

def remove_rule():

    rule = get_rule()

    if rule is None:
        return

    request = {
        "command": "REMOVE",
        "src": rule["src"],
        "dst": rule["dst"],
        "dst_port": rule["dst_port"],
        "protocol": "TCP"
    }

    response = send_request(request)

    if response:
        print(response)


# --------------------------------------------------
# VIEW RULES
# --------------------------------------------------

def view_rules():

    request = {
        "command": "LIST"
    }

    response = send_request(request)

    if response:

        print("\nCURRENT TCP FIREWALL RULES")
        print("---------------------------")
        print("Automatic protection:", "ON" if response.get("automatic") else "OFF (static baseline)")
        print(f"Threshold: {response.get('limit')} new connections in "
              f"{response.get('window_seconds')}s; cooldown {response.get('block_seconds')}s")

        rules = response.get("rules", [])

        if not rules:

            print("No firewall rules configured.")

        else:

            for index, rule in enumerate(rules, start=1):

                print(
                    f"{index}. "
                    f"{rule['src']} -> {rule['dst']}:{rule['dst_port']} | "
                    f"{rule['protocol']} | "
                    f"{rule['action']}"
                )

        for rule in response.get("auto_blocks", []):
            print(f"AUTO BLOCK: {rule['src']} -> {rule['dst']}:{rule['dst_port']} "
                  f"({rule['remaining_seconds']}s remaining)")


def set_automatic():
    answer = input("Automatic protection (ON/OFF): ").strip().upper()
    if answer not in ("ON", "OFF"):
        print("Enter ON or OFF.")
        return
    response = send_request({"command": "AUTO", "enabled": answer == "ON"})
    if response:
        print(response)


# --------------------------------------------------
# MAIN MENU
# --------------------------------------------------

def main():

    while True:

        print("\n========== TCP FIREWALL CLI ==========")
        print("1. Add TCP firewall rule")
        print("2. Remove TCP firewall rule")
        print("3. View firewall rules")
        print("4. Exit")
        print("5. Set automatic protection ON/OFF")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":

            add_rule()

        elif choice == "2":

            remove_rule()

        elif choice == "3":

            view_rules()

        elif choice == "4":

            print("Exiting firewall CLI.")
            break

        elif choice == "5":
            set_automatic()

        else:

            print("Invalid choice. Try again.")


if __name__ == "__main__":

    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nFirewall CLI stopped.")
