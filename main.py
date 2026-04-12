from os import getenv

from src.connection import connect
from dotenv import load_dotenv

load_dotenv()
server_host = getenv('SERVER_HOST', '0.0.0.0')

connect(server_host)
