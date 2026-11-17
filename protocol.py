MAX_MSG_SIZE = 4096

def send_msg(connection , msg):
    data = msg.encode("utf-8")

    if b"\n" in data:
        raise ValueError("A message cannot contain a newline.")

    if len(data) > MAX_MSG_SIZE:
        raise ValueError("Message is too large")

    connection.sendall(data + b"\n")

def rcv_msg(connection, buffer):
    while b"\n" not in buffer:
        if len(buffer) > MAX_MSG_SIZE:
            raise ValueError("Message is too large.")

        data = connection.recv(1024)

        if not data:
            if buffer:
                raise ValueError("Connection closed during a message.")

            return None, b""
        
        buffer += data

    msg, remaining = buffer.split(b"\n", 1)

    if len(msg) > MAX_MSG_SIZE:
        raise ValueError("Message is too large")
    
    return msg.decode("utf-8"), remaining

