
import selectors
import socket
import os
import struct  # For unpacking binary data
import Request
import Response
import cksum
import uuid
from AES import AESCipher
from AES import RSACipher
from func import saveFile, generateUUID

# Default port
DEFAULT_PORT = 1256
port = DEFAULT_PORT
filename = 'port.info'


class Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.file_transfers = {}
        self.AESkeys = {}
        self.registered_user = {}
        self.response = Response.Response()

    def receive_CRC(self, data, conn):

        request = Request.CrcPacket()
        request.unpack(data)
        self.response.payload.clientID = bytes(request.header.clientID)

        if request.header.code in (Request.VALID_CRC, Request.INVALID_CRC_END):
            self.response.header.code = Response.CONFIRM
            self.send_to_client(conn)
            del self.AESkeys[conn]
        else:
            print()

    def receive_file_and_send_crc(self, data, conn):
        # If this is the first packet, initialize the transfer
        if conn not in self.file_transfers:
            self.file_transfers[conn] = {
                'fileName': '',
                'origFileSize': 0,
                'totalPackets': 0,
                'receivedPackets': 0,
                'fileData': b''  # This will accumulate the entire file
            }
            request = Request.SendFilePacket()
            request.unpack(data)
            request.print_info()

        request = Request.SendFilePacket()
        request.unpack(data)

        # Update the ongoing transfer information
        transfer_info = self.file_transfers[conn]
        if transfer_info['receivedPackets'] == 0:
            # Initialize transfer details from the first packet
            transfer_info['fileName'] = request.fileName
            transfer_info['origFileSize'] = request.origFileSize
            transfer_info['totalPackets'] = request.totalPackets

        # Append the chunk of data from this packet
        transfer_info['fileData'] += request.cipher
        transfer_info['receivedPackets'] += 1

        # Check if we've received all packets
        if transfer_info['receivedPackets'] == transfer_info['totalPackets']:
            print(f"All packets received for file: {transfer_info['fileName']}")

            # Decrypt the entire file
            aes = self.AESkeys[conn]
            try:
                decrypted_data = aes['key'].decrypt(transfer_info['fileData'])
                # Avoid decoding as UTF-8
                print(f"Decrypted content: [Binary data of length {len(decrypted_data)}]")
            except Exception as e:
                print(f"Decryption failed: {e}")
                # Handle decryption error (e.g., notify client, log error)
                return

            client_name = self.get_client_name_by_uuid(request.header.clientID)

            # Save the file in binary mode
            try:
                saveFile(client_name, transfer_info['fileName'], decrypted_data)
                print(f"File saved successfully for client {client_name}.\n")
            except Exception as e:
                print(f"Failed to save file: {e}")
                # Handle file saving error
                return

            # Prepare the response
            self.response.payload.clientID = bytes(request.header.clientID)
            self.response.payload.contentSize = struct.pack('<I', len(decrypted_data))
            self.response.payload.fileName = request.fileName.encode('utf-8')  # Assuming fileName is a string
            self.response.payload.CkSum = cksum.readfile(fr'backup\{client_name}\{transfer_info["fileName"]}')

            self.response.setResponseHeader(Response.FILE_RECEIVE_SEND_CRC)

            # Send response to client
            self.send_to_client(conn)

            # Remove the completed transfer
            del self.file_transfers[conn]

        else:
            print(f"Received {transfer_info['receivedPackets']}/{transfer_info['totalPackets']} packets.")

    # get publickey and send AES key with encrypt
    def receive_PublicKey(self, data, conn):

        request = Request.ReceivePublicKeyPacket()
        request.unpack(data)
        uuid_client_id = bytes(request.header.clientID)

        if request.clientName in self.registered_user:
            self.registered_user[request.clientName]['publicKey'] = request.publicKey
            uuid_client_id = self.registered_user[request.clientName]['UUID'].bytes
        else:
            print(f"User {request.clientName} not found")

        encrypted_message = self.genrate_encrypted_AES_key(conn, request.clientName)
        self.response.payload.clientID = uuid_client_id
        self.response.payload.AESKey = encrypted_message
        self.response.setResponseHeader(Response.KEY_RECEIVED_SEND_AES_KEY)

        # send to client
        self.send_to_client(conn)

    def registration_request(self, conn, data):
        request = Request.RegistrationPacket()
        request.unpack(data)

        # check if client already exist
        if request.clientName in self.registered_user:
            self.response.setResponseHeader(Response.REGISTRATION_FAIL)
            self.send_to_client(conn)
        else:
            uuid_v3 = generateUUID(request.clientName)

            self.registered_user[request.clientName] = {
                "UUID": uuid_v3,
                "publicKey": None  # Initialize with None until public key is send later
            }
            print(f"User {request.clientName} registered with UUID: {uuid_v3}\n")

            self.response.payload.clientID = uuid_v3.bytes  # Example ClientID (16 bytes or fewer)
            self.response.setResponseHeader(Response.REGISTRATION_SUCCESS)
            self.send_to_client(conn)

    def reconnect_request(self, conn, data):
        print("***************** ")
        print("***************** ")
        request = Request.RegistrationPacket()
        request.unpack(data)
        self.response.payload.clientID = bytes(request.header.clientID)
        print("***************** ", request.header.clientID)
        # check if user exist and he sent public key
        if (request.clientName not in self.registered_user or self.registered_user[request.clientName]["publicKey"] is
                None):
            self.response.payload.clientID = bytes(request.header.clientID)
            self.response.setResponseHeader(Response.RECONNECTION_DENIED)
            self.send_to_client(conn)
        else:
            self.response.payload.clientID = bytes(request.header.clientID)
            encrypted_message = self.genrate_encrypted_AES_key(conn, request.clientName)
            self.response.payload.AESKey = encrypted_message
            self.response.setResponseHeader(Response.CONFIRM_RECONNECT_SEND_AES_KEY)
            self.send_to_client(conn)

    def genrate_encrypted_AES_key(self, conn, client_name):
        aes = AESCipher()
        self.AESkeys[conn] = {'key': aes}
        public_key = self.registered_user[client_name]["publicKey"]

        # save the public key in file
        rsa_publickey = RSACipher(public_key)
        # Encrypt the AES key with rsa key to send to client
        encrypted_message = rsa_publickey.encryptTRY(aes.key)
        return encrypted_message

    def send_to_client(self, conn):
        data_to_send = self.response.pack()
        self.response.print_t()
        conn.send(data_to_send)
        self.response.clear()

    def accept(self, sock, mask):
        conn, addr = sock.accept()  # Should be ready
        print('Accepted', conn, 'from', addr)
        print()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def startServer(self):
        self.getPort()
        sock = socket.socket()
        sock.bind(('localhost', self.port))

        # Start listening for incoming connections(**Up to 100 pending connections**)
        sock.listen(100)
        sock.setblocking(False)

        # selector should watch for the socket to become ready for reading.
        self.sel.register(sock, selectors.EVENT_READ, self.accept)
        print(f"Server started, listening on ('localhost', {self.port})")
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def read(self, conn, mask1):
        try:
            total_data = bytearray()  # To store all received data
            chunk = conn.recv(1024)  # Read in 1024-byte chunks

            if not chunk:
                # No data received means the client closed the connection
                print("Client closed the connection")
                self.sel.unregister(conn)
                conn.close()
                return

            total_data.extend(chunk)

            # Assuming each request can be fully unpacked from total_data
            request_header = Request.Header()
            request_header.unpack(total_data)

            match request_header.code:
                case Request.REGISTRATION:
                    self.registration_request(conn, total_data)
                case Request.SEND_PUBLIC_KEY:
                    self.receive_PublicKey(total_data, conn)
                case Request.SEND_FILE:
                    self.receive_file_and_send_crc(total_data, conn)
                case Request.VALID_CRC:
                    self.receive_CRC(total_data, conn)
                case Request.INVALID_CRC_SEND_AGAIN:
                    self.receive_CRC(total_data, conn)
                case Request.INVALID_CRC_END:
                    self.receive_CRC(total_data, conn)
                case Request.RECONNECT:
                    self.reconnect_request(conn, total_data)
                case _:
                    print(f"Unknown request code: {request_header.code}")

            # After processing, keep the connection registered for further requests
            self.sel.modify(conn, selectors.EVENT_READ, self.read)

        except Exception as e:
            print(f"Error handling client: {e}")
            self.sel.unregister(conn)
            conn.close()

    def getPort(self):
        try:
            # Check if the file exists
            if os.path.exists(filename):
                # Open the file for reading
                with open(filename, 'r') as file:
                    # Read the port from the file
                    self.port = int(file.read().strip())
            else:
                # If the file doesn't exist, display a warning and use the default port
                print(f"Warning: '{filename}' not found. Using default port {DEFAULT_PORT}.")
        except (ValueError, IOError) as e:
            # In case of an error reading the file or converting to an integer
            print(f"{e}Warning: Failed to read port from '{filename}'. Using default port {DEFAULT_PORT}.")
            self.port = DEFAULT_PORT

    def get_client_name_by_uuid(self, uuid_to_find) -> str:

        # Convert the list of integers to a byte array
        client_id_bytes = bytes(uuid_to_find)
        # Create a UUID object from the byte array
        uuid_obj = uuid.UUID(bytes=client_id_bytes)

        for client_name, info in self.registered_user.items():
            if info["UUID"] == uuid_obj:
                return client_name
        raise ValueError(f"No client found with UUID: {uuid_obj}")
