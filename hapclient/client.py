"""Controller class for interacting with a HAP device."""

import http.client
import json
import uuid

from .model.characteristics import CharacteristicTypes
from .model.services import ServiceTypes
from .protocol import get_session_keys, perform_pair_setup, remove_pairing
from .secure_http import SecureHttp
from .zeroconf import discover_homekit_devices, find_device_ip_and_port


class HapClient:
    """Controller for interacting with an individual HAP device."""

    def __init__(self, device_id, address=None, port=None, pairing_data=None):
        """
        Initialize the HapClient object.

        :param device_id: ID of this device, can be found via discover()
        :param address: IP address of the device
        :param port: HTTP port
        :param pairing_data: existing pairing data
        """
        self.device_id = device_id
        self.pairing_data = pairing_data

        if address is not None and port is not None:
            self.address = address
            self.port = port
        else:
            self.address = None
            self.port = None
            self.find_device()

    def find_device(self):
        """
        Find the device on the network.

        :returns: True on success, False on error
        """
        connection_data = find_device_ip_and_port(self.device_id)
        if connection_data is None:
            return False

        self.address = connection_data['ip']
        self.port = connection_data['port']
        return True

    @staticmethod
    def discover(timeout=1):
        """
        Discover all HAP devices on the network.

        :param timeout: number of seconds after which to stop search
        :returns: a list of dicts, each containing device data
        """
        return discover_homekit_devices(timeout=timeout)

    def identify(self):
        """
        Run the identify routine on a device.

        This can only be done before pairing.

        :returns: True on success, False on error
        """
        # It's impossible to identify if already paired.
        if self.pairing_data:
            return False

        conn = http.client.HTTPConnection(self.address, port=self.port)

        try:
            conn.request('POST', '/identify')
        except (TimeoutError, http.client.HTTPException, OSError):
            return None

        status = conn.getresponse().code
        conn.close()

        if status == 204:
            return True

        return False

    def pair(self, pin):
        """
        Attempt to pair with a device.

        :param pin: the pairing PIN
        :returns: True on success, False on error
        """
        # Do not allow the user to pair again.
        if self.pairing_data:
            return False

        if not pin:
            return False

        conn = http.client.HTTPConnection(self.address, port=self.port)

        pairing_id = str(uuid.uuid4())
        pairing_data = perform_pair_setup(conn, pin, pairing_id)
        if pairing_data:
            self.pairing_data = pairing_data
            return True

        return False

    def unpair(self):
        """
        Unpair the controller from the device.

        :returns: True on success, False on error
        """
        if not self.pairing_data:
            return False

        conn = http.client.HTTPConnection(self.address, port=self.port)

        return remove_pairing(conn, self.pairing_data)

    def get_accessories(self):
        """
        Get the accessory attribute database from the device.

        :returns: dict of accessory attributes on success, None on error
        """
        if not self.pairing_data:
            return None

        conn = http.client.HTTPConnection(self.address, port=self.port)

        keys = get_session_keys(conn, self.pairing_data)
        if not keys:
            return None

        controller_to_accessory_key, accessory_to_controller_key = keys

        sec_http = SecureHttp(conn.sock,
                              accessory_to_controller_key,
                              controller_to_accessory_key)
        response = sec_http.get('/accessories')
        data = json.loads(response.read().decode())
        for acc in data['accessories']:
            for svc in acc['services']:
                svc['type'] = ServiceTypes[svc['type']]

                for char in svc['characteristics']:
                    char['type'] = CharacteristicTypes[char['type']]

        conn.close()

        return data

    def get_characteristics(self, characteristics, meta=False, perms=False,
                            type_=False, ev=False):
        """
        Read a set of characteristics.

        :param characteristics: list of characteristics ID to get
        :param meta: whether or not to retrieve metadata, i.e. format, unit ...
        :param perms: whether or not to retrieve permission data
        :param type_: whether or not to retrieve the characteristic type
        :param ev: whether or not to retrieve the 'ev' property
        :returns: dict of characteristic attributes on success, None on error
        """
        if not self.pairing_data or not isinstance(characteristics, list) or \
                len(characteristics) < 1:
            return None

        conn = http.client.HTTPConnection(self.address, port=self.port)

        keys = get_session_keys(conn, self.pairing_data)
        if not keys:
            return None

        controller_to_accessory_key, accessory_to_controller_key = keys

        sec_http = SecureHttp(conn.sock,
                              accessory_to_controller_key,
                              controller_to_accessory_key)

        url = '/characteristics?id=' + ','.join(characteristics)
        if meta:
            url += '&meta=1'
        if perms:
            url += '&perms=1'
        if type_:
            url += '&type=1'
        if ev:
            url += '&ev=1'

        response = sec_http.get(url)
        data = json.loads(response.read().decode())
        conn.close()

        return data

    def set_characteristics(self, characteristics):
        """
        Modify a set of characteristics.

        :param characteristics: dict of characteristics ID to set, id -> val
        :returns: True on success, False on error
        """
        if not self.pairing_data or not isinstance(characteristics, dict) or \
                len(characteristics) < 1:
            return None

        conn = http.client.HTTPConnection(self.address, port=self.port)

        keys = get_session_keys(conn, self.pairing_data)
        if not keys:
            return None

        controller_to_accessory_key, accessory_to_controller_key = keys

        sec_http = SecureHttp(conn.sock,
                              accessory_to_controller_key,
                              controller_to_accessory_key)

        clist = []
        for cid, value in characteristics.items():
            parts = cid.split('.')
            aid = int(parts[0])
            iid = int(parts[1])
            clist.append({'aid': aid, 'iid': iid, 'value': value})

        body = json.dumps({'characteristics': clist})
        response = sec_http.put('/characteristics', body)
        status = response.code
        conn.close()

        if status == 204:
            return True

        return False
