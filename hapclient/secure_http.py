"""Handler for HomeKit's secure HTTP protocol."""

from nacl.bindings import (crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt)
import http.client
import io

from .http_parser import HttpParser


class SecureHttp:
    """
    Class to handle HomeKit's secure HTTP protocol.

    This is defined in chapter 5.5 page 70ff of the HAP specification.
    """

    class SocketWrapper:
        """Fake socket wrapper."""

        def __init__(self, data):
            """
            Initialize the object.

            :param data: the response data
            """
            self.data = data

        def makefile(self, arg):
            """
            Make this socket into a file-like object.

            :returns: a BytesIO object with the response data
            """
            return io.BytesIO(self.data)

    class HTTPResponseWrapper:
        """HTTPResponse wrapper for complete data."""

        def __init__(self, data):
            """
            Initialize the object.

            :param data: the response data
            """
            self.data = data
            self.status = 200

        def read(self):
            """
            Read from the response body.

            :returns: the full response
            """
            return self.data

    def __init__(self, sock, a2c_key, c2a_key):
        """
        Initialize the secure HTTP class.

        The required keys can be obtained with get_session_keys.

        :param sock: the socket over which the communication takes place
        :param a2c_key: the key used for the communication between accessory
                        and controller
        :param c2a_key: the key used for the communication between controller
                        and accessory
        """
        self.sock = sock
        self.a2c_key = a2c_key
        self.c2a_key = c2a_key
        self.c2a_counter = 0
        self.a2c_counter = 0

    def get(self, target):
        """
        Perform a GET request.

        :param target: the target URL
        :returns: HTTP response object on success, None on error
        """
        data = 'GET {} HTTP/1.1\r\n\r\n'.format(target).encode()

        return self._handle_request(data)

    def put(self, target, body, ctype='application/hap+json'):
        """
        Perform a PUT request.

        :param target: the target URL
        :param body: the message body
        :param ctype: the content-type
        :returns: HTTP response object on success, None on error
        """
        if isinstance(body, str):
            body = body.encode()
        elif isinstance(body, bytearray):
            body = bytes(body)

        request = 'PUT {} HTTP/1.1\r\n'.format(target)
        headers = 'Content-Type: {}\r\n'.format(ctype)
        headers += 'Content-Length: {}\r\n\r\n'.format(len(body))

        data = request.encode() + headers.encode() + body

        return self._handle_request(data)

    def post(self, target, body, ctype='application/hap+json'):
        """
        Perform a POST request.

        :param target: the target URL
        :param body: the message body
        :param ctype: the content-type
        :returns: HTTP response object on success, None on error
        """
        if isinstance(body, str):
            body = body.encode()
        elif isinstance(body, bytearray):
            body = bytes(body)

        request = 'POST {} HTTP/1.1\r\n'.format(target)
        headers = 'Content-Type: {}\r\n'.format(ctype)
        headers += 'Content-Length: {}\r\n\n'.format(len(body))

        data = request.encode() + headers.encode() + body

        return self._handle_request(data)

    def _handle_request(self, data):
        """
        Encrypt request data and send it.

        :param data: data to encrypt and send
        :returns: HTTP response object on success, None on error
        """
        if len(data) > 1024:
            return None

        len_bytes = len(data).to_bytes(2, byteorder='little')
        cnt_bytes = self.c2a_counter.to_bytes(8, byteorder='little')
        self.c2a_counter += 1
        ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(
            data,
            len_bytes,
            bytes([0, 0, 0, 0]) + cnt_bytes,
            self.c2a_key)
        self.sock.send(len_bytes + ciphertext)
        return self._handle_response()

    @staticmethod
    def _parse(chunked_data):
        """
        Parse chunked HTTP data.

        :param chunked_data: chunked HTTP data
        :returns: reconstructed data
        """
        splitter = b'\r\n'
        tmp = chunked_data.split(splitter, 1)
        length = int(tmp[0].decode(), 16)
        if length == 0:
            return bytearray()

        chunk = tmp[1][:length]
        tmp[1] = tmp[1][length + 2:]
        return chunk + SecureHttp._parse(tmp[1])

    def _handle_response(self):
        """
        Handle an HTTP response and decrypt it.

        :returns: HTTP response object
        """
        # following the information from page 71 about HTTP Message splitting:
        # The blocks start with 2 byte little endian defining the length of the
        # encrypted data (max 1024 bytes) followed by 16 byte authTag.
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

            # if the the amount of data in tmp is not length + 2 + 16, the
            # block is not complete yet
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
                    bytes([0, 0, 0, 0]) +
                    self.a2c_counter.to_bytes(8, byteorder='little'),
                    self.a2c_key)
                if dec is not False:
                    result += dec
                self.a2c_counter += 1

                # check how long next block will be
                if len(tmp) >= 2 and \
                        int.from_bytes(tmp[0:2], 'little') <= 1024:
                    length = int.from_bytes(tmp[0:2], 'little')
                else:
                    length = 0

            if result.startswith(b'HTTP/1.1'):
                parser = HttpParser()
                ret = parser.execute(result, len(result))
                if ret == len(result) and parser.is_message_complete():
                    break
            elif result.endswith(b'\r\n0\r\n\r\n'):
                break

        if result.startswith(b'HTTP/1.1'):
            r = http.client.HTTPResponse(self.SocketWrapper(result))
            r.begin()
            return r
        else:
            # If the device just sends chunked data instead of a proper HTTP
            # response, handle it.
            data = SecureHttp._parse(result)
            return self.HTTPResponseWrapper(data)
