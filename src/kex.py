import socket
from dataclasses import dataclass
import os

@dataclass
class SSHPacket:
    padding_length: int = 0
    payload: bytes = b""
    random_padding: bytes = b""


def recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""

    while len(buf) < n:
        need = n - len(buf)
        chunk = s.recv(need)
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk

    return buf


def read_packet(s: socket.socket) -> bytes:
    packet_length = int.from_bytes(recv_exact(s, 4), byteorder='big')
    rest = recv_exact(s, packet_length)
    padding_length = rest[0]
    payload_length = packet_length - padding_length - 1
    payload = rest[1: 1 + payload_length]
    return payload


def write_packet(s: socket.socket, payload: bytes):
    payload_length = len(payload)
    padding_length = calc_padding(payload_length)
    packet_length = padding_length + payload_length + 1
    random_padding = os.urandom(padding_length)
    packet = (packet_length.to_bytes(4, byteorder='big') +
              padding_length.to_bytes(1, byteorder='big') +
              payload +
              random_padding)
    s.send(packet)


def calc_padding(payload: int) -> int:
    padding = 4
    is_valid = padding_valid(payload, padding)
    while not is_valid:
        padding += 1
        is_valid = padding_valid(payload, padding)
    return padding


def padding_valid(payload: int, padding: int) -> bool:
    return (4 + 1 + payload + padding) % 8 == 0
