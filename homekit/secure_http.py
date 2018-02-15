from nacl.bindings import (crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt)
import fcntl
import http.client
import io
import os

from .pyparser import HttpParser


class SecureHttp:
    """
    Class to helf in the handling of HTTP requests and responses that are performed following chapter 5.5 page 70ff of
    the HAP specification.
    """

    class Wrapper:
        def __init__(self, data):
            self.data = data

        def makefile(self, arg):
            return io.BytesIO(self.data)

    class HTTPResponseWrapper:
        def __init__(self, data):
            self.data = data
            self.status = 200

        def read(self):
            return self.data

    def __init__(self, sock, a2c_key, c2a_key):
        """
        Initializes the secure HTTP class. The required keys can be obtained with get_session_keys

        :param sock: the socket over which the communication takes place
        :param a2c_key: the key used for the communication between accessory and controller
        :param c2a_key: the key used for the communication between controller and accessory
        """
        self.sock = sock
        self.a2c_key = a2c_key
        self.c2a_key = c2a_key
        self.c2a_counter = 0
        self.a2c_counter = 0

    def get(self, target):
        data = 'GET {tgt} HTTP/1.1\n\n'.format(tgt=target)

        return self._handle_request(data)

    def put(self, target, body):
        headers = 'Host: hap-770D90.local\n' + \
                  'Content-Type: application/hap+json\n' + \
                  'Content-Length: {len}\n'.format(len=len(body))
        data = 'PUT {tgt} HTTP/1.1\n{hdr}\n{body}'.format(tgt=target, hdr=headers, body=body)
        return self._handle_request(data)

    def post(self, target, body):
        headers = 'Content-Type: application/hap+json\n' + \
                  'Content-Length: {len}\n'.format(len=len(body))
        data = 'POST {tgt} HTTP/1.1\n{hdr}\n{body}'.format(tgt=target, hdr=headers, body=body)

        return self._handle_request(data)

    def _handle_request(self, data):
        assert len(data) < 1024
        len_bytes = len(data).to_bytes(2, byteorder='little')
        cnt_bytes = self.c2a_counter.to_bytes(8, byteorder='little')
        self.c2a_counter += 1
        ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(
            data.encode(),
            len_bytes,
            bytes([0, 0, 0, 0]) + cnt_bytes,
            self.c2a_key)
        self.sock.send(len_bytes + ciphertext)
        return self._handle_response()

    @staticmethod
    def _parse(chunked_data):
        splitter = b'\r\n'
        tmp = chunked_data.split(splitter, 1)
        length = int(tmp[0].decode(), 16)
        if length == 0:
            return bytearray()

        chunk = tmp[1][:length]
        tmp[1] = tmp[1][length + 2:]
        return chunk + SecureHttp._parse(tmp[1])

    def _handle_response(self):
        # following the information from page 71 about HTTP Message splitting:
        # The blocks start with 2 byte little endian defining the length of the encrypted data (max 1024 bytes)
        # followed by 16 byte authTag
        tmp = bytearray()
        result = bytearray()
        exp_len = 512
        while True:
            data = self.sock.recv(exp_len)
            if not data:
                break

            if len(data) < 2:
                continue

            tmp += data
            length = int.from_bytes(tmp[0:2], 'little')

            # if the the amount of data in tmp is not length + 2 bytes for length + 16 bytes for the tag, the block
            # is not complete yet
            while len(tmp) >= length + 18:
                tmp = tmp[2:]

                block = tmp[0:length]
                tmp = tmp[length:]

                tag = tmp[0:16]
                tmp = tmp[16:]

                # Decrypt this block
                dec = crypto_aead_chacha20poly1305_ietf_decrypt(
                    bytes(block + tag),
                    length.to_bytes(2, byteorder='little'),
                    bytes([0, 0, 0, 0]) + self.a2c_counter.to_bytes(8, byteorder='little'),
                    self.a2c_key)
                if dec is not False:
                    result += dec
                self.a2c_counter += 1

                # check how long next block will be
                if len(tmp) >= 2 and int.from_bytes(tmp[0:2], 'little') <= 1024:
                    length = int.from_bytes(tmp[0:2], 'little')
                else:
                    length = 0

            if result.startswith(b'HTTP/1.1'):
                parser = HttpParser()
                ret = parser.execute(result, len(result))
                if ret == len(result) and parser.is_message_complete():
                    break
            else:
                if result.endswith(b'\r\n0\r\n\r\n'):
                    break

        #
        #   I expected a full http response but the first real homekit accessory (Koogeek-P1) just replies with body
        #   in chunked mode...
        #
        if result.startswith(b'HTTP/1.1'):
            r = http.client.HTTPResponse(SecureHttp.Wrapper(result))
            r.begin()
            return r
        else:
            data = SecureHttp._parse(result)
            return self.HTTPResponseWrapper(data)
