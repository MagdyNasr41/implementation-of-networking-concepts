# Megzawicol: The OSI Model Implementation Playground

**Keywords:** OSI Model, TCP/IP, TLS Handshake, Symmetric Encryption, Data Link Layer, Network Layer, Transport Layer, Session Layer, Presentation Layer, Application Layer, Segmentation, Cyclic Redundancy Check (CRC).

## Project Overview

**Project Name:** Megzawicol

The name "Megzawicol" is created from my nickname, "Megzawi" and the word "Protocol". This project is a hands-on exploration and implementation of core network concepts, focusing on how data is transferred through the seven layers of the OSI Model (Open Systems Interconnection Model), from the application layer down to the physical layer.

It demonstrates a complete simulated network connection between a client and a server, using security elements like a simplified TLS 1.3 Handshake to establish a secure, symmetric key for encryption.

## Features
<img width="5667" height="2834" alt="osi_model_7_layers" src="https://github.com/user-attachments/assets/550678d4-f897-47c3-9162-81cef561a48d" />

This simulation implements the core functionality of all seven OSI layers for sending data from a client to a server:

- **Application Layer (L7):** Structures a simulated HTTP POST request message.
- **Presentation Layer (L6):** Encrypts the application data using a derived symmetric key (simulating HTTPS/TLS).
- **Session Layer (L5):** Manages connection state by adding a session ID and timestamp to the packet.
- **Transport Layer (L4):** Segments the data, assigns sequence numbers (tag), and simulates a basic TCP-like acknowledgment (ACK) mechanism for reliability.
- **Network Layer (L3):** Adds IP addressing and handles fragmentation if the transport segment exceeds the simulated MTU (Maximum Transmission Unit).
- **Data Link Layer (L2):** Adds MAC addressing, breaks packets into frames, and calculates a Cyclic Redundancy Check (CRC) in the trailer for data integrity.
- **Physical Layer (L1):** Converts frames into a raw bit stream for transmission across the simulated network socket.

The process is mirrored in reverse on the server side to decapsulate, verify, and decrypt the original application message.

## How to Run the Project

### Prerequisites
You need Python 3.8+ installed.

### Setup

Clone the repository and install the dependencies:

### Execution

The project requires two terminals to run concurrently: one for the server and one for the client.

#### 1. Start the Server

In your first terminal:

```bash
python server.py
```

The server will print: `[Server] Listening on 127.0.0.1:65432...`

#### 2. Start the Client

In your second terminal:

```bash
python client.py
```

The client will connect, perform the TLS handshake, send the data through all the layers, and then disconnect. You will see the output in both terminals detailing the operations at each layer.

## Project Files

- **client.py:** Contains the client-side implementation, which initiates the connection and pushes data through the seven layers of the OSI model for transmission.
- **server.py:** Contains the server-side implementation, which listens for connections and processes incoming data by reversing the OSI layer process (Physical up to Application).
- **layers.py:** Contains all the function definitions for each of the seven OSI layers and necessary utility functions (e.g., key derivation, segmentation, CRC).

## Future Work
I will be implementing more network concepts such as UDP protocol simulation code, the difference between a synchroized and asynchronized concepts, NAT, Proxy Servers, etc.. .
