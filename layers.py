# layers.py
from cryptography.fernet import Fernet
import random
import string
import base64
import hashlib
import uuid
import time 
import math
import json
import zlib 
import ast

# ------------------------------------------
# Utilities
# ------------------------------------------
PUBLIC_KEY = "MAGDYLOVEMOS" # Simulated public key for KDF

_sessions = {} # To track active sessions

SEGMENT_SIZE = 50  # bytes per segment for transport and network layer 

FRAME_PAYLOAD_SIZE = 50  # bytes per frame payload for data link layer

def generate_random_string(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# This function ensures the symmetric key is 16 bytes (128 bits)
def Key_Derivation_Function_KDF(client_key: str, public_key: str, server_key: str) -> str:

    symmetric_key = client_key + public_key + server_key
    symmetric_key = symmetric_key.encode()
    symmetric_key = hashlib.sha256(symmetric_key).digest()
    symmetric_key = base64.urlsafe_b64encode(symmetric_key)

    return symmetric_key

# ------------------------------------------
# 7- Application Layer (HTTP-like request)
# It prepares the data to be sent over the network. (Body, Headers, Method, Path, cookies, etc.)
# ------------------------------------------
def application_layer(message):

    print("[Application Layer] Preparing HTTP-like data for transmission...")

    # Build a simulated HTTP POST request
    http_request = f"""POST /api/v1/messages HTTP/1.1
                    Host: localhost
                    User-Agent: PythonClient/1.0
                    Content-Type: application/json
                    Cookie: sessionid=abc123; theme=dark; csrftoken=xyz789
                    Authorization: Bearer dummy_token_123
                    Accept: application/json
                    Content-Length: {len(message)}
                    Body: {message}
                    """
    return http_request

# ---------------------------------------------
# 6- PRESENTATION LAYER (Encryption)
# It encrypts the data using symmetric encryption (HTTPS).
# ---------------------------------------------
def presentation_layer(payload, key):

    print("[Presentation Layer] Encrypting data (HTTPS)...")
    cipher = Fernet(key)
    encrypted = cipher.encrypt(payload.encode())
    print(f"[Presentation Layer] ✅ Data encrypted successfully.")

    return encrypted.decode()

# ---------------------------------------------
# 5- SESSION LAYER (Adding a Session ID) 
# It creates a state so that if inturruption takes place we can resume from that state. It is important for synchronization.
# ---------------------------------------------
def session_layer(encrypted_payload, session_id=None):

    print("[Session Layer] Adding session id and its corresponding time information...")
    if session_id is None:
        # Establish a new session
        session_id = str(uuid.uuid4())
        _sessions[session_id] = {
            "start_time": time.time(),
            "last_active": time.time(),
            "status": "ACTIVE"
        }
        print(f"[Session Layer] ✅ New session established: {session_id}")
    else:
        # Update existing session
        if session_id in _sessions:
            _sessions[session_id]["last_active"] = time.time()
            print(f"[Session Layer] ✅ Existing session active: {session_id}")
        else:
            print(f"[Session Layer] Invalid session, creating new one.")
            return session_layer(encrypted_payload)
        
    with open("active_sessions.json", "w") as f:
        json.dump(_sessions, f, indent=4)

    # Wrap data with session context
    return {
        "session_id": session_id,
        "timestamp": time.time(),
        "payload": encrypted_payload
    }


# ---------------------------------------------
# 4- TRANSPORT LAYER (Segmentation and Reliability)
# It segments the data into smaller chunks and simulates reliability mechanisms like acknowledgments.
# ---------------------------------------------
def transport_layer(conn, session_packet, src_port=49500, dst_port=65432):
  
    print("[Transport Layer] Segmenting data for reliable transport...")

    # Convert to string for simplicity
    serialized = str(session_packet)
    total_len = len(serialized)
    num_segments = math.ceil(total_len / SEGMENT_SIZE)

    print("[Transport Layer] Creating Segments...")
    segments = []
    seq_num = 1 
    for i in range(num_segments):
        payload = serialized[i*SEGMENT_SIZE:(i+1)*SEGMENT_SIZE]
        segment = {
            "src_port": src_port,
            "dst_port": dst_port,
            "tag": seq_num,
            "ack": 0,  # will be filled by server later
            "payload": payload
        }
        seq_num += 1
        segments.append(segment)

    print("[Transport Layer] Sending Segments:")
    # Simulate ACK for each segment
    for i, seg in enumerate(segments):
        a = json.dumps(seg).encode()
        conn.sendall(json.dumps(seg).encode())
        print(f" from client to server → Sent segment #{seg['tag']} (src_port={seg['src_port']}, dst_port={seg['dst_port']})")

        # Wait for ACK from server
        ack = conn.recv(1024).decode()
        print(f" ack received from server to client ← {ack} for segment {seg['tag']}")
    
    print("[Transport Layer] ✅ All segments sent and acknowledged.")

    # Notify server that transport-layer transmission is complete
    end_signal = json.dumps({"type": "END_TRANSPORT"}).encode()
    conn.sendall(end_signal)

    return segments

# -----------------------------------------------------
# 3- Network Layer (Adding IP)
# -----------------------------------------------------
def network_layer(segments, src_ip="192.168.1.10", dst_ip="192.168.1.20", MTU=50):

    print("[Network Layer] Encapsulating transport segments into IP packets with fragmentation...")
    packets = []

    for seg in segments:
        seg_data = json.dumps(seg)  # serialize the segment
        total_len = len(seg_data)
        num_frags = math.ceil(total_len / MTU)

        # print(f"Segment #{seg['tag']} is {total_len} bytes → {num_frags} fragments")

        for i in range(num_frags):
            fragment_payload = seg_data[i*MTU:(i+1)*MTU]
            packet = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "Megzawicol",
                "fragment_offset": i,
                "more_fragments": (i < num_frags - 1),
                "payload": fragment_payload
            }
            packets.append(packet)

    print(f"[Network Layer] ✅ Done creating {len(packets)} packets with IP out of {len(segments)} segments.")

    return packets

# -----------------------------------------------------
# 2- Data Link Layer (Adding MAC)
# -----------------------------------------------------
def data_link_layer(packets, src_mac="placeholder_src_mac", dst_mac="placeholder_dst_mac"):

    print("[Data Link Layer] Framing IP packets with MAC addresses and CRC...")
    frames = []
    for packet in packets:
        # Convert packet to string for simplicity
        serialized = str(packet)
        total_len = len(serialized)
        num_segments = math.ceil(total_len / FRAME_PAYLOAD_SIZE)

        for i in range(num_segments):
            # Slice the payload for this frame
            payload = serialized[i*FRAME_PAYLOAD_SIZE:(i+1)*FRAME_PAYLOAD_SIZE]

            # Compute CRC for this segment
            crc = zlib.crc32(payload.encode())

            # Construct frame
            frame = {
                "header": {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "frame_no": i + 1,
                    "protocol": "Megzawicol"
                },
                "payload": payload,
                "trailer": {
                    "crc": crc # Cyclic Redundancy Check, in server we recalculate and compare to ensure data integrity
                }
            }

            frames.append(frame)
            # print(f"[Data Link Layer] Frame {i+1} created: payload_len={len(payload)}, CRC={crc}")

    print(f"[Data Link Layer] ✅Total {len(frames)} frame(s) ready for transmission.")
    return frames

# -----------------------------------------------------
# 1- Physical Layer (Binary Transmission with Noise Simulation)
# -----------------------------------------------------
def physical_layer(conn, frames, error_rate=0.000001, transmission_speed=1e6):

    print("[Physical Layer] Converting frames into raw bits and transmitting...")

    try:
        transmitted_bits = []
        for i, frame in enumerate(frames):
            frame_data = json.dumps(frame)
            bits = ''.join(format(ord(c), '08b') for c in frame_data)  # convert to binary string
            
            # # Simulate noise: randomly flip bits with given error rate
            # noisy_bits = ''.join(
            #     '1' if (bit == '0' and random.random() < error_rate) else
            #     '0' if (bit == '1' and random.random() < error_rate) else
            #     bit
            #     for bit in bits
            # )
            
            # Simulate transmission delay (based on bits and speed)
            delay = len(bits) / transmission_speed
            time.sleep(delay / 1000)  # scaled down for realism

            # print("bits:",bits)
            # Send bits followed by delimiter
            conn.sendall(bits.encode() + b"\nEND_FRAME\n")

            transmitted_bits.append(bits)
            # print(f"  ⚡ Frame {i+1} → {len(bits)} bits transmitted ({delay:.5f}s simulated)")
        # print("Transmitted bits:", transmitted_bits)
        print("[Physical Layer] ✅All bits transmitted successfully.")
        successful_transmissions = True
    except Exception as e:
        print(f"[Physical Layer] ⚠️ Transmission error: {e}")
        successful_transmissions = False
    return successful_transmissions

# -----------------------------# -----------------------------# -----------------------------# -----------------------------# -----------------------------

# -----------------------------
# Converting recieved Bits to Frames 
# -----------------------------
def receive_physical_layer(conn):

    print("[Physical Layer Server] Receiving bits and converting back to frames...")
    buffer = ""
    frames = []

    while True:
        data = conn.recv(4096)
        if not data:
            break  # client disconnected

        buffer += data.decode()

        # Split on END_FRAME delimiter
        while "END_FRAME\n" in buffer:
            bits, buffer = buffer.split("END_FRAME\n", 1)
            bits = bits.strip()
            if not bits:
                continue
            try:
                # Convert bits → text → JSON
                chars = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)) # it takes the bits converting it 8-bits by 8-bits
                frame = json.loads(chars)
                frames.append(frame)
                # print(f"[Physical Server] Received frame #{len(frames)} ({len(bits)} bits)")
            except Exception as e:
                print(f"[Physical Layer Server] ⚠️ Frame decode error: {e}")

    print(f"[Physical Server] ✅ {len(frames)} frame(s) reconstructed.")
    return frames

# ---------------------------------------------
# Converting recieved frames to network packets
# ---------------------------------------------
def receive_data_link_layer(frames):

    print("[Data Link Server] Reassembling frames into IP packets...")
    packets = []
    current_buf = None  # accumulating string for current packet
    packet_count = 0

    for idx, frame in enumerate(frames):
        header = frame.get("header", {})
        frame_no = header.get("frame_no", 1)

        # If frame_no == 1 and we already have a buffer -> finalize previous packet
        if frame_no == 1 and current_buf is not None:
            # finalize previous packet
            try:
                # parse Python literal (sender used str(packet))
                pkt_obj = ast.literal_eval(current_buf)
                # ensure payload (which was json.dumps(seg)) is converted to dict
                if isinstance(pkt_obj.get("payload"), str):
                    try:
                        pkt_obj["payload"] = json.loads(pkt_obj["payload"])
                    except Exception:
                        # leave as-is if not valid JSON
                        pass
                packets.append(pkt_obj)
                packet_count += 1
            except Exception as e:
                print(f"[Data Link Layer Server] ⚠️ Failed to parse packet #{packet_count+1}: {e}")
            # start new buffer with current frame payload
            current_buf = frame["payload"]
        else:
            # either first frame or continuation
            if current_buf is None:
                current_buf = frame["payload"]
            else:
                current_buf += frame["payload"]

    # finalize last packet if buffer exists
    if current_buf is not None:
        try:
            pkt_obj = ast.literal_eval(current_buf)
            if isinstance(pkt_obj.get("payload"), str):
                try:
                    pkt_obj["payload"] = json.loads(pkt_obj["payload"])
                except Exception:
                    pass
            packets.append(pkt_obj)
            packet_count += 1
        except Exception as e:
            print(f"[Data Link Layer Server] ⚠️ Failed to parse final packet: {e}")

    print(f"[Data Link Layer Server] ✅ Reassembled {packet_count} IP packet(s).")
    return packets

# ---------------------------------------------
# Converting recieved packets to segments 
# ---------------------------------------------
def receive_network_layer(packets):
    print("[Network Layer Server] Decapsulating IP packets into transport segments...")
    segments = []
    for i, packet in enumerate(packets):
        try:
            src_ip = packet.get("src_ip", "unknown")
            dst_ip = packet.get("dst_ip", "unknown")
            protocol = packet.get("protocol", "Megzawicol")
            segment = packet.get("payload")

            if segment is not None:
                segments.append(segment)
                # print(f" Received IP packet #{i+1}: {src_ip} → {dst_ip}, Protocol={protocol}")
            else:
                print(f"  ⚠️ Packet #{i+1} missing payload, skipping.")
        except Exception as e:
            print(f"  ⚠️ Error processing packet #{i+1}: {e}")

    print(f"[Network Layer Server] ✅ Extracted {len(segments)} transport segment(s).")
    return segments

# ---------------------------------------------
# TRANSPORT LAYER (Acknowledgment)
# ---------------------------------------------
def acknowledge_transport_layer(conn):
    full_message = ""
    while True:
        packet = conn.recv(1024)
        # print("[Transport Server] Packet received at acknowledge_transport_layer:", packet)
        if not packet:
            break

        segment = json.loads(packet.decode())
        # Check for transport-layer end signal
        if segment.get("type") == "END_TRANSPORT":
            print("[Transport Layer Server] ✅ All segments are acknowledged.")
            break
        tag = segment["tag"]
        src_port = segment["src_port"]
        dst_port = segment["dst_port"]
        data = segment["payload"]
        # print(f"[Transport Server] Received segment #{tag} from {src_port} → {dst_port}: {data}")
        full_message += data

        # Send ACK back to client
        ack_msg = json.dumps({
            "ack": tag,
            "status": "OK",
            "message": f"ACK for segment {tag}"
        })
        conn.sendall(ack_msg.encode())

    # print(f"[Transport Server] Reassembled full message: {full_message}")
    # return full_message

# ---------------------------------------------
# SESSION LAYER (Validation)
# ---------------------------------------------
def receive_session_layer(packets):

    print("[Session Layer Server] Validating session context...")

    with open("active_sessions.json", "r") as f:
        saved_sessions = json.load(f)
        _sessions.update(saved_sessions)

    print("sessions: ", _sessions)

    if not isinstance(packets, list) or len(packets) == 0:
        print("[Session Layer Server] ⚠️ No packets received for session layer.")
        return None

    all_payloads = []  # collect payloads from each packet

    for i, packet in enumerate(packets):
        try:
            # Ensure packet is a dict (in case something slipped as string)
            if isinstance(packet, str):
                packet = json.loads(packet)

            session_id = packet.get("session_id")
            if not session_id:
                print(f"[Session Layer Server] ⚠️ Packet {i}: No session_id found — assigning temporary session.")
                session_id = f"temp-{int(time.time())}"
                packet["session_id"] = session_id

            # Create or update session record
            if session_id not in _sessions:
                print(f"[Session Layer Server] ⚠️ New session {session_id} detected — creating entry.")
                _sessions[session_id] = {
                    "start_time": time.time(),
                    "last_active": time.time(),
                    "status": "NEW"
                }
            else:
                _sessions[session_id]["last_active"] = time.time()
                _sessions[session_id]["status"] = "RESUMED"
                print(f"[Session Layer Server] ✅ Session validated and active: {session_id}")

            # Optionally check for timeout
            elapsed = time.time() - _sessions[session_id]["last_active"]
            if elapsed > 300:
                print(f"[Session Layer Server] ⚠️ Session {session_id} expired, resetting.")
                _sessions[session_id]["status"] = "EXPIRED"

            # Collect payload for reassembly
            if "payload" in packet:
                all_payloads.append(packet["payload"])
            else:
                print(f"[Session Layer Server] ⚠️ Packet {i} missing payload field.")

        except json.JSONDecodeError as e:
            print(f"[Session Layer Server] ⚠️ JSON error in packet {i}: {e}")
        except Exception as e:
            print(f"[Session Layer Server] ⚠️ Error processing packet {i}: {e}")

    # Combine all payloads
    reconstructed_payload = "".join(all_payloads)
    print(f"[Session Layer Server] ✅ Reconstructed session payload ({len(all_payloads)} segments).")

    return reconstructed_payload


# ---------------------------------------------
# Presentation Layer (Decryption)
# ---------------------------------------------
def receive_presentation_layer(data, key):
    print("[Presentation Layer] Decrypting data (HTTPS)...")
    cipher = Fernet(key)
    decrypted = cipher.decrypt(data.encode())
    return decrypted.decode()


# ------------------------------------------
# Application Layer (HTTP-like request)
# ------------------------------------------
def receive_application_layer(response):
    print("[Application Layer] Data received by application!")
    print(response)
    return response
