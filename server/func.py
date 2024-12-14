import os
import uuid
import struct

# Constants for unpacking binary data
CLIENT_ID_SIZE = 16
CLIENT_NAME_SIZE = 255
AES_KEY_SIZE = 160
PUBLIC_KEY_SIZE = 160
CKSUM_SIZE = 4
CONTENT_SIZE = 4
ORIG_FILE_SIZE = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKET_SIZE = 2
FILE_NAME_SIZE = 255
HEADER_FORMAT = '<B H 16B I'  # 1 byte for version, 2 bytes for code, 16 bytes for ClientID, 4 bytes for payload_size
PAYLOAD_HEADER_FORMAT = 'I'  # 4 bytes for payload_size
# Total expected size includes the header and the 4-byte payload size
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

DEF_VAL = 0
DEF_VERSION = 3
REGISTRATION = 825
SEND_PUBLIC_KEY = 826
RECONNECT = 827
SEND_FILE = 828
VALID_CRC = 900
INVALID_CRC_SEND_AGAIN = 901
INVALID_CRC_END = 902

REGISTRATION_SUCCESS = 1600
REGISTRATION_FAIL = 1601
KEY_RECEIVED_SEND_AES_KEY = 1602
FILE_RECEIVE_SEND_CRC = 1603
CONFIRM = 1604
CONFIRM_RECONNECT_SEND_AES_KEY = 1605
RECONNECTION_DENIED = 1606
ERROR = 1607

# Mapping of response codes to descriptive strings
RESPONSE_CODE_MAPPING = {
    REGISTRATION_SUCCESS: "REGISTRATION_SUCCESS",
    REGISTRATION_FAIL: "REGISTRATION_FAIL",
    KEY_RECEIVED_SEND_AES_KEY: "KEY_RECEIVED_SEND_AES_KEY",
    FILE_RECEIVE_SEND_CRC: "FILE_RECEIVE_SEND_CRC",
    CONFIRM: "CONFIRM",
    CONFIRM_RECONNECT_SEND_AES_KEY: "CONFIRM_RECONNECT_SEND_AES_KEY",
    RECONNECTION_DENIED: "RECONNECTION_DENIED",
    ERROR: "ERROR",
    REGISTRATION: "REGISTRATION",
    SEND_PUBLIC_KEY: "SEND_PUBLIC_KEY",
    RECONNECT: "RECONNECT",
    SEND_FILE: "SEND_FILE",
    VALID_CRC: "VALID_CRC",
    INVALID_CRC_SEND_AGAIN: "INVALID_CRC_SEND_AGAIN",
    INVALID_CRC_END: "INVALID_CRC_END",
}


def saveFile(client_name, file_name, file_content):
    """
    Saves the received file content to the specified directory.
    """

    directory = os.path.join('backup', client_name)
    file_path = os.path.join(directory, file_name)

    # Create the directory if it doesn't exist
    os.makedirs(directory, exist_ok=True)

    # Open the file in binary write mode and write the binary data
    with open(file_path, 'wb') as file:
        file.write(file_content)

    print(f"File saved successfully to {file_path}")


def generateUUID(name):
    namespace = uuid.NAMESPACE_DNS
    uuid_v3 = uuid.uuid3(namespace, name)
    return uuid_v3


def format_bytes(data: bytes, limit=64) -> str:
    if not data:
        return "None"
    hex_str = data.hex()
    if len(hex_str) > limit:
        return hex_str[:limit] + "..."
    return hex_str


def decode_bytes(data: bytes) -> str:
    try:
        return data.decode('utf-8').rstrip('\x00') if data else "None"
    except UnicodeDecodeError:
        return data.hex()