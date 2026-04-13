import socket
from dataclasses import dataclass
import os
import secrets

# Простое число p для группы 14 (2048 бит) - RFC 3526
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
# Генератор группы
g = 2


@dataclass
class SSHPacket:
    padding_length: int = 0
    payload: bytes = b""
    random_padding: bytes = b""


def recv_exact(s: socket.socket, n: int) -> bytes:
    """Читает ровно n байт из сокета. Если соединение закрылось раньше - кидает ошибку."""
    buf = b""

    while len(buf) < n:
        need = n - len(buf)
        chunk = s.recv(need)
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk

    return buf


def read_packet(s: socket.socket) -> bytes:
    """Читает один SSH-пакет из сокета и возвращает его payload - без служебных полей и padding."""
    packet_length = int.from_bytes(recv_exact(s, 4), byteorder='big')
    rest = recv_exact(s, packet_length)
    padding_length = rest[0]
    payload_length = packet_length - padding_length - 1
    payload = rest[1: 1 + payload_length]
    return payload


def write_packet(s: socket.socket, payload: bytes):
    """Оборачивает payload в SSH-пакет и отправляет в сокет."""
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
    """Вычисляет минимальный padding (не менее 4 байт), чтобы размер пакета был кратен 8."""
    padding = 4
    is_valid = padding_valid(payload, padding)
    while not is_valid:
        padding += 1
        is_valid = padding_valid(payload, padding)
    return padding


def padding_valid(payload: int, padding: int) -> bool:
    """Проверяет, что при данном padding размер пакета делится на 8."""
    return (4 + 1 + payload + padding) % 8 == 0


def build_kexinit() -> bytes:
    """Собирает payload SSH_MSG_KEXINIT - список алгоритмов, которые мы поддерживаем."""
    kex = ["diffie-hellman-group14-sha256"]
    host_key = ["rsa-sha2-256"]
    encryption = ["aes128-ctr"]
    mac = ["hmac-sha2-256"]
    compression = ["none"]

    msg_type = int(20).to_bytes(1, byteorder='big')
    cookie = os.urandom(16)

    return (msg_type +
            cookie +
            encode_name_list(kex) +
            encode_name_list(host_key) +
            encode_name_list(encryption) +
            encode_name_list(encryption) +
            encode_name_list(mac) +
            encode_name_list(mac) +
            encode_name_list(compression) +
            encode_name_list(compression) +
            encode_name_list([]) +
            encode_name_list([]) +
            b'\x00' +
            encode_uint32(0))


def encode_uint32(n: int) -> bytes:
    """Упаковывает число в 4 байта big-endian - стандартный SSH uint32."""
    return n.to_bytes(4, byteorder='big')


def encode_name_list(names: list[str]) -> bytes:
    """Кодирует список алгоритмов в SSH name-list - длина строки (4 байта) + строка через запятую."""
    name_list = ",".join(names)
    name_list_utf8 = name_list.encode('utf-8')
    name_list_uint32 = encode_uint32(len(name_list_utf8))
    return name_list_uint32 + name_list_utf8


def send_kexinit(s: socket.socket):
    """Отправляет SSH_MSG_KEXINIT серверу - наш список поддерживаемых алгоритмов."""
    kexinit = build_kexinit()
    write_packet(s, kexinit)


def recv_kexinit(s: socket.socket) -> bytes:
    """Читает SSH_MSG_KEXINIT от сервера. Если пришло что-то другое - кидает ошибку."""
    packet = read_packet(s)
    if packet[0] != 20:
        raise ValueError(f"expected SSH_MSG_KEXINIT (20), got {packet[0]}")
    return packet


def encode_mpint(n: int) -> bytes:
    """Кодирует большое целое число в SSH mpint - длина (4 байта) + байты числа big-endian."""
    length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(length, byteorder='big')
    if n_bytes[0] & 0x80:
        n_bytes = b"\x00" + n_bytes
    return encode_uint32(len(n_bytes)) + n_bytes


def send_kexdh_init(s):
    """Генерирует DH-параметры и отправляет SSH_MSG_KEXDH_INIT. Возвращает (x, e) для дальнейших вычислений."""
    x = secrets.randbelow(p)
    e = pow(g, x, p)
    payload = (30).to_bytes(1, 'big') + encode_mpint(e)
    write_packet(s, payload)
    return x, e
