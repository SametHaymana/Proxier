import socket
import struct
import threading

def external_connection_test(bind_ip, bind_port, message):
    """
    Simulates an external connection to the proxy's bound port.
    """
    try:
        # Wait for a brief moment to ensure the bind is ready
        import time
        time.sleep(1)

        # Connect to the bound port
        print(f"External connection: Connecting to {bind_ip}:{bind_port}")
        ext_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ext_sock.connect((bind_ip, bind_port))

        # Send a message to the proxy
        ext_sock.sendall(message.encode())
        ext_sock.close()
        print("External connection: Message sent!")
    except Exception as e:
        print(f"External connection error: {e}")

def test_socks5_bind(proxy_host, proxy_port, bind_port, message):
    """
    Tests SOCKS5 BIND functionality.
    """
    try:
        # Connect to the proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_host, proxy_port))

        # SOCKS5 handshake
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, 1 method (no auth)
        response = sock.recv(2)
        if response != b"\x05\x00":
            print(f"Handshake failed: {response}")
            return

        # Request BIND
        bind_request = b"\x05\x02\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", bind_port)
        sock.sendall(bind_request)

        # Receive the BIND response
        response = sock.recv(10)
        if response[1] != 0x00:
            print(f"BIND request failed: {response[1]}")
            return

        # Extract the bound IP and port
        bind_ip = socket.inet_ntoa(response[4:8])
        bind_port = struct.unpack(">H", response[8:10])[0]
        print(f"Proxy bound to {bind_ip}:{bind_port}")

        # Start a thread to simulate an external connection
        threading.Thread(target=external_connection_test, args=(bind_ip, bind_port, message), daemon=True).start()

        # Wait for the proxy to forward the connection
        incoming_response = sock.recv(1024)
        print("Connection received through proxy!")

        # Read the message forwarded by the proxy
        received_message = sock.recv(1024).decode()
        print(f"Message received: {received_message}")

        # Close the socket
        sock.close()

    except Exception as e:
        print(f"Test failed: {e}")

# Proxy and test details
proxy_host = "127.0.0.1"  # SOCKS5 proxy address
proxy_port = 1080         # SOCKS5 proxy port
bind_port = 8080          # Desired bind port (set to 0 for dynamic allocation)
test_message = "Hello, SOCKS5 Proxy!"

# Run the test
test_socks5_bind(proxy_host, proxy_port, bind_port, test_message)
