# client.py
import socket
from layers import *
import sys

HOST = '127.0.0.1'
PORT = 65432

# ------------------------------------------
# TLS Handshake Simulation (client-side)
# ------------------------------------------
def perform_tls_handshake_client_v13(conn):
    client_private_key = generate_random_string()
    print(f"[TLS] → ClientHello: TLSv1.3, cipher=AES256-GCM, client is sending client_private_key={client_private_key}")
    # Send the client_private_key to the server
    message = {"type": "ClientHello", "client_private_key": client_private_key}
    conn.sendall(json.dumps(message).encode())
    # Receive ServerHello
    data = conn.recv(4096).decode()
    server_msg = json.loads(data)
    if server_msg["type"] == "ServerHello":
        print(f"[TLS] ← ServerHello: accepted TLSv1.3, server_private_key={server_msg['server_private_key']}")
        global symmetric_key
        symmetric_key = Key_Derivation_Function_KDF(client_private_key, PUBLIC_KEY, server_msg['server_private_key'])
        print(f"[TLS] ✅ Handshake complete, symmetric key: {symmetric_key}")
        
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # --- TLS Handshake ---
    perform_tls_handshake_client_v13(s) # client sends supported TLS version, cipher suites, random bytes.

    # --- Prepare HTTP-like message ---
    request = {
        "method": "POST",
        "path": "/api/login",
        "headers": {
            "Host": "example.com",
            "User-Agent": "OSIClient/1.0",
            "Content-Type": "application/json",
            "Cookie": "sessionid=abc123"
        },
        "body": {"username": "alice", "password": "secret123"}
    }

    payload = application_layer(request)
    # print("Vanilla payload:", payload)
    encrypted_payload = presentation_layer(payload, symmetric_key)
    # print("Encrypted payload:", encrypted_payload)
    session_packet = session_layer(encrypted_payload) 
    # print("Session packet:", session_packet)
    acknowledged_segments = transport_layer(s, session_packet) # (tagging and segmenting)
    # print("Acknowledged segments:", acknowledged_segments)
    packets = network_layer(acknowledged_segments, src_ip="192.168.1.10", dst_ip="192.168.1.20") # (adding IP headers and further segmenting)
    # print("Network packets:", packets)
    frames = data_link_layer(packets)
    # print("Data link frames:", frames)
    successful_transmissions = physical_layer(s, frames)
    if not successful_transmissions:
        print("[Client] ⚠️ Transmission failed at Physical Layer.")
        sys.exit(1)
