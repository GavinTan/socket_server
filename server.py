import hmac
import os
import hashlib
import traceback
import subprocess
from socketserver import BaseRequestHandler, ThreadingTCPServer
import logging
import json
import struct


log = logging.getLogger()
console = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(filename)s: %(levelname)s  %(message)s')
console.setFormatter(formatter)
log.addHandler(console)
log.setLevel(logging.INFO)


class EchoHandler(BaseRequestHandler):
    secret_key = b'abcd11234'

    def server_authenticate(self, connection, secret_key):
        message = os.urandom(32)
        connection.send(message)
        h = hmac.new(secret_key, message, digestmod=hashlib.md5)
        digest = h.digest()
        response = connection.recv(len(digest))
        return hmac.compare_digest(digest, response)

    def run_cmd(self, msg):
        midst = str(msg.decode('utf-8')).split(" ")
        if len(midst) >= 2 and midst[0] == "cmd":
            try:
                command = subprocess.Popen(msg.decode('utf-8')[4:], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                outs, errs = command.communicate()
                if command.returncode != 0:
                    log.error(errs.decode('utf-8'))
                    return errs
                return outs
            except Exception as e:
                log.error(e)
                traceback.print_exc()
        else:
            return msg

    def handle(self):
        if not self.server_authenticate(self.request, self.secret_key):
            self.server.server_close()
            return
        log.info(f'Connection from: {self.client_address}')
        while True:
            msg = self.request.recv(8192)
            if len(msg) > 0:
                if msg == b'quit':
                    log.info(f'{self.client_address} connect close')
                    self.server.server_close()
                    self.server.shutdown()
                    break
                else:
                    logging.debug(f"Receive: {msg.decode('utf-8')}")
                    r = self.run_cmd(msg)
                    d = {'size': len(r)}
                    h = struct.pack('i', len(json.dumps(d)))
                    self.request.sendall(h)
                    self.request.sendall(json.dumps(d).encode('utf-8'))
                    self.request.sendall(r)

            else:
                log.info(f'{self.client_address} disconnect')
                break


if __name__ == '__main__':
    ThreadingTCPServer.allow_reuse_address = True
    serv = ThreadingTCPServer(('', 7316), EchoHandler)
    log.info("Server is running on port: 7316")
    serv.serve_forever()
