
from func import *


class Response:
    def __init__(self):
        self.header = ResponseHeader()
        self.payload = ResponsePayload()

    def pack(self) -> bytes:
        return self.header.pack() + self.payload.pack()

    def setResponseHeader(self, code: int):
        self.header.code = code
        # Calculate payload size based on which fields are populated
        self.header.payloadSize = self.payload.calculate_payload_size()

    def print_t(self):
        print("=== Response ===")
        self.header.print_t()
        self.payload.print_t()

    def clear(self):
        self.payload.clear()


class ResponseHeader:
    def __init__(self):
        self.version = DEF_VERSION
        self.code = DEF_VAL
        self.payloadSize = DEF_VAL
        self.SIZE = 7  # Not used in this context

    def pack(self) -> bytes:
        return struct.pack(
            '< B H I',
            self.version,       # 1 byte
            self.code,          # 2 bytes
            self.payloadSize,   # 4 bytes
        )

    def print_t(self):
        code_str = RESPONSE_CODE_MAPPING.get(self.code, "UNKNOWN_CODE")
        print(f"--- ResponseHeader ---")
        print(f"Version: {self.version} ({'DEF_VERSION' if self.version == DEF_VERSION else 'UNKNOWN'})")
        print(f"Code: {self.code} ({code_str})")
        print(f"Payload Size: {self.payloadSize}")


class ResponsePayload:
    def __init__(self):
        self.clientID: bytes = b""
        self.publicKey: bytes = b""
        self.AESKey: bytes = b""
        self.contentSize: bytes = b""
        self.fileName: bytes = b""
        self.CkSum: bytes = b""

    def pack(self) -> bytes:
        # Prepare a dynamic format string and data list for struct packing
        format_string = '<'  # Little-endian format
        data_to_pack = []

        # Only include clientID if it is filled
        if self.clientID:
            format_string += f'{CLIENT_ID_SIZE}s'
            data_to_pack.append(self.clientID)

        # Only include publicKey if it is filled
        if self.publicKey:
            format_string += f'{PUBLIC_KEY_SIZE}s'
            data_to_pack.append(self.publicKey)

        # Only include AESKey if it is filled
        if self.AESKey:
            format_string += f'{AES_KEY_SIZE}s'
            data_to_pack.append(self.AESKey)

        # Only include contentSize if it is filled
        if self.contentSize:
            format_string += f'{CONTENT_SIZE}s'
            data_to_pack.append(self.contentSize)

        # Only include fileName if it is filled
        if self.fileName:
            format_string += f'{FILE_NAME_SIZE}s'
            data_to_pack.append(self.fileName)

        # Only include CkSum if it is filled
        if self.CkSum:
            format_string += f'{CKSUM_SIZE}s'
            data_to_pack.append(self.CkSum)

        # If no attributes were filled, return an empty byte string
        if not data_to_pack:
            return b""

        # Pack the data using the dynamically created format string
        data = struct.pack(format_string, *data_to_pack)
        return data

    def calculate_payload_size(self) -> int:
        size = 0
        if self.clientID:
            size += CLIENT_ID_SIZE
        if self.publicKey:
            size += PUBLIC_KEY_SIZE
        if self.AESKey:
            size += AES_KEY_SIZE
        if self.contentSize:
            size += CONTENT_SIZE
        if self.fileName:
            size += FILE_NAME_SIZE
        if self.CkSum:
            size += CKSUM_SIZE
        return size

    def print_t(self):
        print(f"--- ResponsePayload ---")
        if self.clientID:
            print(f"ClientID: {format_bytes(self.clientID)}")
        if self.publicKey:
            print(f"PublicKey: {format_bytes(self.publicKey)}")
        if self.AESKey:
            print(f"Decrypted AES Key: {format_bytes(self.AESKey)}")
        if self.contentSize:
            print(f"Content Size: {int.from_bytes(self.contentSize, byteorder='little')}")
        if self.fileName:
            print(f"File Name: {decode_bytes(self.fileName)}")
        if self.CkSum:
            print(f"Checksum: {int.from_bytes(self.CkSum, byteorder='little')}")
        print()

    def clear(self):
        self.clientID = b""
        self.publicKey = b""
        self.AESKey = b""
        self.contentSize = b""
        self.fileName = b""
        self.CkSum = b""
