from os import getenv
from src.connection import connect
from src.kex import send_kexinit, recv_kexinit
from dotenv import load_dotenv

load_dotenv()
server_host = getenv('SERVER_HOST', '0.0.0.0')

s = connect(server_host)

send_kexinit(s)
payload = recv_kexinit(s)
print("got KEXINIT, msg_type = ", payload[0])
