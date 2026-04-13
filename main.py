from os import getenv
from src.connection import connect
from src.kex import send_kexinit, recv_kexinit, send_kexdh_init, recv_kexdh_reply, send_newkeys, recv_newkeys
from dotenv import load_dotenv

load_dotenv()
server_host = getenv('SERVER_HOST', '0.0.0.0')

s = connect(server_host)

send_kexinit(s)
payload = recv_kexinit(s)
print("got KEXINIT, msg_type = ", payload[0])
x, _ = send_kexdh_init(s)
K, K_S, f, signature = recv_kexdh_reply(s, x)
send_newkeys(s)
recv_newkeys(s)
