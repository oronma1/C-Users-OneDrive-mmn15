from func import *


class Header:
    def __init__(self):
        self.clientID = DEF_VAL
        self.version = DEF_VERSION
        self.code = DEF_VAL
        self.payloadSize = DEF_VAL
        self.SIZE = HEADER_SIZE

    def unpack(self, data: bytes):
        """Little Endian unpack Request Header with validation."""
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Data too short for Header. Expected at least {HEADER_SIZE} bytes, got {len(data)} bytes.")

        try:
            unpacked = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            self.version = unpacked[0]
            self.code = unpacked[1]
            self.clientID = list(unpacked[2:18])  # 16 bytes
            self.payloadSize = unpacked[18]
        except struct.error as e:
            raise ValueError(f"Failed to unpack Header: {e}")

        # Validate version
        if not (self.version == DEF_VERSION):
            raise ValueError(f"Invalid version: {self.version}. Must be between 0 and 255.")

        # Validate code
        if self.code not in RESPONSE_CODE_MAPPING:
            raise ValueError(f"Unknown response code: {self.code}.")

        # Validate clientID
        if not isinstance(self.clientID, list) or len(self.clientID) != CLIENT_ID_SIZE:
            raise ValueError(f"Invalid clientID: {self.clientID}. Must be a list of 16 integers.")

        # Validate payloadSize
        if self.payloadSize < DEF_VAL:
            raise ValueError(f"Invalid payloadSize: {self.payloadSize}. Must be non-negative.")

    def print_info(self):
        client_id_bytes = bytes(self.clientID)
        hex_string = client_id_bytes.hex()
        print(f"Version: {self.version}, Code: {self.code}, ClientID: {hex_string}, "
              f"Payload Size: {self.payloadSize}")


class SendFilePacket:
    def __init__(self):
        self.header = Header()
        self.contentSize = DEF_VAL
        self.origFileSize = DEF_VAL
        self.packetNumber = DEF_VAL
        self.totalPackets = DEF_VAL
        self.fileName = ""
        self.cipher = b""

    def unpack(self, data: bytes):
        """Unpack SendFilePacket with validation."""
        try:
            # Ensure data is sufficient for header
            if len(data) < HEADER_SIZE:
                raise ValueError(
                    f"Data too short for SendFilePacket. Expected at least {HEADER_SIZE} bytes, got {len(data)} bytes.")

            # Unpack the header
            self.header.unpack(data)

            # After header, expect 12 bytes for contentSize, origFileSize, packetNumber, totalPackets
            expected_size_after_header = HEADER_SIZE + 12
            if len(data) < expected_size_after_header:
                raise ValueError(
                    f"Data too short for SendFilePacket fields. Expected at least {expected_size_after_header}"
                    f" bytes, got {len(data)} bytes.")

            # Unpack contentSize, origFileSize, packetNumber, totalPackets
            unpacked_fields = struct.unpack('<I I H H', data[HEADER_SIZE:HEADER_SIZE + 12])
            self.contentSize = unpacked_fields[0]
            self.origFileSize = unpacked_fields[1]
            self.packetNumber = unpacked_fields[2]
            self.totalPackets = unpacked_fields[3]

            # Validate contentSize and origFileSize
            if self.contentSize < DEF_VAL:
                raise ValueError(f"Invalid contentSize: {self.contentSize}. Must be non-negative.")
            if self.origFileSize < DEF_VAL:
                raise ValueError(f"Invalid origFileSize: {self.origFileSize}. Must be non-negative.")

            # Unpack fileName
            file_name_start = HEADER_SIZE + 12
            file_name_end = file_name_start + FILE_NAME_SIZE
            if len(data) < file_name_end:
                raise ValueError(
                    f"Data too short for fileName. Expected at least {file_name_end} bytes, got {len(data)} bytes.")

            file_name_data = data[file_name_start:file_name_end]
            self.fileName = decode_bytes(file_name_data)

            # Unpack cipher data
            cipher_start = file_name_end
            cipher_end = cipher_start + self.contentSize
            if len(data) < cipher_end:
                raise ValueError(
                    f"Data too short for cipher data. Expected at least {cipher_end} bytes, got {len(data)} bytes.")

            cipher_data = data[cipher_start:cipher_end]
            self.cipher = cipher_data  # Already bytes

        except struct.error as e:
            raise ValueError(f"Failed to unpack SendFilePacket: {e}")

    def print_info(self):
        print("--- Receive filePacket  ---")
        print(f"Packet {self.packetNumber}/{self.totalPackets} for file: {self.fileName}")
        print(f"Content Size: {self.contentSize}")
        print(f"Original File Size: {self.origFileSize}")
        print(f"Cipher Data: {format_bytes(self.cipher)}")
        print()


class CrcPacket:
    def __init__(self):
        self.header = Header()
        self.FileName = ""

    def unpack(self, data: bytes):
        """Unpack CrcPacket with validation."""
        try:
            # Ensure data is sufficient for header
            if len(data) < HEADER_SIZE:
                raise ValueError(
                    f"Data too short for CrcPacket. Expected at least {HEADER_SIZE} bytes, got {len(data)} bytes.")

            # Unpack the header
            self.header.unpack(data)

            # After header, expect FILE_NAME_SIZE bytes for FileName
            expected_total_size = HEADER_SIZE + FILE_NAME_SIZE
            if len(data) < expected_total_size:
                raise ValueError(
                    f"Data too short for CrcPacket FileName. Expected at least {expected_total_size} bytes, got {len(
                        data)} bytes.")

            # Unpack FileName
            name_data = data[HEADER_SIZE:expected_total_size]
            self.FileName = decode_bytes(name_data)
            self.print_info()
        except struct.error as e:
            raise ValueError(f"Failed to unpack CrcPacket: {e}")

    def print_info(self):
        print("--- Receive CrcPacket (valid or not) ---")
        self.header.print_info()
        print(f"FileName: {self.FileName}")
        print()


class RegistrationPacket:
    def __init__(self):
        self.header = Header()
        self.clientName = ""

    def unpack(self, data: bytes):
        """Unpack RegistrationPacket with validation."""
        try:
            # Ensure data is sufficient for header
            if len(data) < HEADER_SIZE:
                raise ValueError(
                    f"Data too short for RegistrationPacket. Expected at least {HEADER_SIZE} bytes, got {len(data)}"
                    f" bytes.")

            # Unpack the header
            self.header.unpack(data)

            # After header, expect CLIENT_NAME_SIZE bytes for clientName
            expected_total_size = HEADER_SIZE + CLIENT_NAME_SIZE
            if len(data) < expected_total_size:
                raise ValueError(
                    f"Data too short for RegistrationPacket clientName. Expected at least {expected_total_size}"
                    f" bytes, got {len(data)} bytes.")

            # Unpack clientName
            name_data = data[HEADER_SIZE:expected_total_size]
            self.clientName = decode_bytes(name_data)
            self.print_info()

        except struct.error as e:
            raise ValueError(f"Failed to unpack RegistrationPacket: {e}")

    def print_info(self):
        if self.header.code == RECONNECT:
            print("--- Receive ReconnectPacket Request ---")
        else:
            print("--- Receive RegistrationPacket Request---")
        self.header.print_info()
        print(f"Client name: {self.clientName}")
        print()


class ReceivePublicKeyPacket:
    def __init__(self):
        self.header = Header()
        self.clientName = ""
        self.publicKey = b""

    def unpack(self, data: bytes):
        """Unpack ReceivePublicKeyPacket with validation."""
        try:
            # Ensure data is sufficient for header
            if len(data) < HEADER_SIZE:
                raise ValueError(
                    f"Data too short for ReceivePublicKeyPacket. Expected at least {HEADER_SIZE} bytes, got {len(data)}"
                    f" bytes.")

            # Unpack the header
            self.header.unpack(data)

            # After header, expect CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE bytes
            expected_total_size = HEADER_SIZE + CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE
            if len(data) < expected_total_size:
                raise ValueError(
                    f"Data too short for ReceivePublicKeyPacket. Expected at least {expected_total_size} bytes, got "
                    f"{len(data)} bytes.")

            # Unpack clientName
            name_data = data[HEADER_SIZE:HEADER_SIZE + CLIENT_NAME_SIZE]
            self.clientName = decode_bytes(name_data)

            # Unpack publicKey
            public_key_data = data[HEADER_SIZE + CLIENT_NAME_SIZE:expected_total_size]
            self.publicKey = public_key_data  # Stored as bytes
            self.print_info()

        except struct.error as e:
            raise ValueError(f"Failed to unpack ReceivePublicKeyPacket: {e}")

    def print_info(self):
        print("--- Receive PublicKeyPacket ---")
        self.header.print_info()
        print(f"Client name: {self.clientName}")
        print(f"Public Key: {format_bytes(self.publicKey)}")
        print()
