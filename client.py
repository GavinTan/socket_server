import socket
import hmac
import hashlib
import time


def client_authenticate(connection, secret_key):
    """
    Authenticate client to a remote service.
    connection represents a network connection.
    secret_key is a key known only to both client/server.
    """
    message = connection.recv(32)
    h = hmac.new(secret_key, message, digestmod=hashlib.md5)
    digest = h.digest()
    connection.send(digest)


def connserver(host, port):
    secret_key = b'abcd112341'
    connect = False
    while True:
        try:
            if not connect:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                client_authenticate(s, secret_key)
                connect = True
            print("\n[*] Please input command:")
            data = input()
            if not data:
                continue
            s.sendall(data.encode('utf-8'))
            print("[+] Send %s:%s -> %s" % (host, str(connPort), data))
            msg = ''
            time.sleep(0.1)
            while True:
                try:
                    recvdata = s.recv(1024, 0x40)
                    msg += str(recvdata, 'utf-8')
                except BlockingIOError:
                    break
            print(f"[+] Receive : \n{msg}")
            if data == "close session":
                s.close()
                break
        except socket.error as e:
            print(e)
            print(f'{host}:{port} reconnect...')
            connect = False
        time.sleep(1)


if __name__ == "__main__":
    connPort = 7316

    connserver('172.16.7.14', connPort)
