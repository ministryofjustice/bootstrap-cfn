import paramiko
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException
import socket

def is_ssh_up(host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username='nobody', password='badpassword', timeout=5)
        return True
    except (AuthenticationException, BadHostKeyException):
        return True
    except socket.error:
        pass
    return False
