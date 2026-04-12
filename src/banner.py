import socket


def get_banner(s: socket.socket, buflen: int =1024):
    """Читает баннер (identification string) от SSH-сервера и возвращает его."""
    return s.recv(buflen)


def send_banner(s: socket.socket, banner: bytes):
    """Отправляет баннер (identification string) на SSH-сервер."""
    s.sendall(banner)
