# server.py 
# run with: watchmedo auto-restart --pattern="*.py" --recursive /usr/local/bin/python3 /Users/lumionasr/Downloads/server.py  

import socket
from layers import *

HOST = '127.0.0.1'
PORT = 65432

# ------------------------------------------
# TLS Handshake Simulation (server-side)
# ------------------------------------------
def perform_tls_handshake_server_v13(conn):
    # Receive ClientHello
    data = conn.recv(4096).decode()
    print("vanilla data received:", data)
    client_msg = json.loads(data)
    if client_msg["type"] == "ClientHello":
        print(f"[TLS] ← ClientHello: server received client_private_key={client_msg['client_private_key']}")
        server_private_key = generate_random_string()
        print(f"[TLS] → ServerHello: server sending server_private_key={server_private_key}")
        response = {"type": "ServerHello", "server_private_key": server_private_key}
        conn.sendall(json.dumps(response).encode())
        global symmetric_key
        symmetric_key = Key_Derivation_Function_KDF(client_msg['client_private_key'], PUBLIC_KEY, server_private_key)
        print(f"[TLS] ✅ Handshake complete, symmetric key: {symmetric_key}")

# ------------------------------------------
# CRC Verification (Data Link Layer trailer)
# ------------------------------------------
def verify_crc(frame):
    """Check if CRC in trailer matches payload's CRC."""
    payload = frame["payload"]
    received_crc = frame["trailer"]["crc"]
    computed_crc = zlib.crc32(payload.encode())

    if received_crc == computed_crc:
        return True
    else:
        return False
    
# ------------------------------------------
# Helper Function
# ------------------------------------------
def separate_packets(packets):
    
    list_of_packets = []
    start_index = 0

    for end_index, _ in enumerate(packets):
        
        # packets[start_index] == '}'  is end if a packet, and packets[start_index + 1] == '{' is start of a new one
        if packets[end_index] == '}' and (end_index + 1 == len(packets) or packets[end_index + 1] == '{'):
            current_packet = packets[start_index:end_index+1]
            start_index = end_index + 1
            list_of_packets.append(json.loads(current_packet))

    return list_of_packets

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[Server] Listening on {HOST}:{PORT}...")

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            # FIRST: Perform TLS Version 1.3 Handshake
            perform_tls_handshake_server_v13(conn)

            # --- Receive packets at Network Layer ---
            try:
                # SECOND: Acknowledge segments for the Transport Layer
                acknowledge_transport_layer(conn)

                # THIRD: Receieve transmitted bits at Physical Layer
                frames = receive_physical_layer(conn)
                # print("Frames received at server:", frames)
                
                # CRC Verification to make sure frames are not corrupted
                for frame in frames:
                    if not verify_crc(frame):
                        print("[Server] ⚠️ Detected corrupted frame. Aborting processing.")
                        break
                print("[Server] ✅ All frames passed CRC check.")
                
                # FOURTH: Process Data Link Layer
                packets = receive_data_link_layer(frames)
                # print("Packets received at server:", packets)

                # FIFTH: Process Network Layer
                segments = receive_network_layer(packets)
                # print("Segments received at server:", segments)

                segments_string = ''
                for segment in segments:
                    segments_string += segment

                packets = separate_packets(segments_string)

                print(f"✅ Extracted {len(packets)} packets.")
                
                # SIXTH: Process Presentation Layer
                session_payload = receive_session_layer(packets)
                # print("Session payload received at server:", session_payload)

                session_payload = ast.literal_eval(session_payload) # Convert double quote string to dict t
   
                # Now extract the encrypted payload
                payload_encrypted = session_payload["payload"]

                # SEVENTH: Decrypt it
                decrypted_payload = receive_presentation_layer(payload_encrypted, symmetric_key)
                print("Decrypted payload at server:", decrypted_payload)

            except json.JSONDecodeError as e:
                print(f"[Server] ⚠️ Error decoding JSON: {e}")
            except Exception as e:
                print(f"[Server] ⚠️ Error: {e}")

            print(f"[Server] Client {addr} disconnected.\n")

        # print("Will open new connection") 

        # # Applying the OSI Model layers to the response and sending it back to the client:
        # response = {"status": "200 OK", "message": "Login successful"}
        # payload = application_layer(json.dumps(response))
        # print("Vanilla payload:", payload)
        # encrypted_payload = presentation_layer(payload, symmetric_key)
        # # print("Encrypted payload:", encrypted_payload)
        # session_packet = session_layer(encrypted_payload) 
        # # print("Session packet:", session_packet)
        # acknowledged_segments = transport_layer(conn, session_packet) # (tagging and segmenting)
        # # print("Acknowledged segments:", acknowledged_segments)
        # packets = network_layer(acknowledged_segments, src_ip="192.168.1.10", dst_ip="192.168.1.20") # (adding IP headers and further segmenting)
        # # print("Network packets:", packets)
        # frames = data_link_layer(packets)
        # # print("Data link frames:", frames)
        # successful_transmissions = physical_layer(conn, frames)
