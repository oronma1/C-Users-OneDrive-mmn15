
# Secure File Transfer System

This project implements a secure file transfer system that uses AES encryption for files and RSA for key exchange between a client and server. The system ensures that file transfers are encrypted and verified for integrity using CRC checks. It also includes mechanisms for client registration and reconnection.

## Project Structure

### C++ Files

- **AESCipher.cpp/h**: Implements AES encryption and decryption in CBC mode. The `AESWrapper` class manages encryption and decryption, with keys exchanged securely via RSA.
  
- **Base64W.cpp/h**: Implements Base64 encoding and decoding, useful for converting binary data such as keys into ASCII format.

- **cksum.cpp/h**: Provides CRC checksum calculation functions used to ensure the integrity of transferred files.

- **Client.cpp/h**: Defines the client-side logic for handling registration, public key exchange, file transfer, and CRC checks.

- **functions.cpp/h**: Contains utility functions such as reading specific lines from files, converting between hex and decimal, and managing configuration data.

- **main.cpp**: The entry point for the client application, which connects to the server and initiates the secure file transfer process.

- **Request.h**: Defines the structure of various client requests, including registration, file transfer, and CRC validation.

- **Response.cpp/h**: Handles deserializing responses from the server, including responses for file transfer and registration.

- **RSACipher.cpp/h**: Manages RSA encryption and decryption. It handles key generation, encrypting AES keys, and decrypting messages with private keys.

- **socket.cpp/h**: Manages the client’s network connection to the server, including sending and receiving encrypted data.

### Python Files

- **AES.py**: Implements AES encryption and decryption in Python. It is used on the server side to decrypt files received from the client.

- **cksum.py**: Implements CRC checksum calculation in Python, similar to the UNIX `cksum` command.

- **func.py**: Contains utility functions for saving files and generating UUIDs for clients.

- **main.py**: Starts the server, which listens on a specified port for incoming client connections.

- **Request.py**: Defines the structure of client requests, including file transfer, CRC validation, and registration.

- **Response.py**: Handles server responses, including sending back AES keys and file CRC information.

- **server.py**: Implements the server-side logic for managing client connections, file transfers, public key exchange, and CRC validation.

### Configuration

- **transfer.info.txt**: This file contains the connection information for the client, including host, client name, and file name:
  ```
  127.0.0.1:2003
  Michael Jackson
  oronFile.txt
  ```

- **port.info**: This file contains the port number on which the server listens for client connections.

## Features

- **Secure File Transfer**: Files are encrypted with AES and sent securely from the client to the server. AES keys are exchanged using RSA encryption.
  
- **Public Key Infrastructure**: RSA is used to encrypt the AES keys, ensuring that the AES keys are not exposed during transmission.

- **CRC Validation**: Ensures the integrity of transferred files. The server computes a CRC checksum for each file and compares it to the client's value to detect corruption.

- **Client Registration and Reconnection**: The server manages client registration, storing public keys and UUIDs for each client. Clients can reconnect using their UUID and public key.

## Setup and Usage

### Prerequisites

- **C++ Compiler**: Required for compiling the C++ components.
- **Python 3.x**: Required for running the server-side Python scripts.
- **Crypto++**: Required for cryptographic operations in the C++ files.
- **Boost**: Used for networking in C++ (Boost.Asio).

### Steps to Run

1. **Compile the C++ Code**:
   Compile the C++ files into an executable using your preferred C++ compiler. For example:
   ```bash
   g++ -o client_exec Client.cpp AESCipher.cpp Base64W.cpp cksum.cpp RSACipher.cpp socket.cpp functions.cpp -lboost_system -lcrypto++
   ```

2. **Start the Server**:
   Run the `main.py` script to start the server:
   ```bash
   python main.py
   ```

3. **Configure Transfer Information**:
   Ensure that the `transfer.info.txt` file contains the correct connection info:
   ```
   127.0.0.1:2003
   Michael Jackson
   oronFile.txt
   ```

4. **Run the Client Executable**:
   Execute the compiled C++ client:
   ```bash
   ./client_exec
   ```

5. **File Transfer**:
   - The client will attempt to register, send its public key, and transfer an encrypted file specified in `transfer.info.txt`.
   - The server will decrypt the file, verify it using CRC, and send a response to the client.

## Contributing

If you'd like to contribute to this project, feel free to fork the repository, make changes, and submit a pull request. All contributions are welcome.

## License

This project is licensed under the Boost Software License. See the LICENSE file for details.
