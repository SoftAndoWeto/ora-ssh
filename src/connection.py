import socket

from src.banner import get_banner, send_banner


def connect(host: str, port: int =22):
    """Открывает TCP-соединение, читает баннер от сервера и выводит его.
    Отправляет свой баннер: SSH-2.0-ora-ssh_0.1. Возвращает сокет."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    banner = get_banner(s)
    send_banner(s, banner)
    return s
