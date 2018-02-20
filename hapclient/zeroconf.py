"""Zeroconf wrappers for finding HAP devices."""

from socket import inet_ntoa
from time import sleep
from zeroconf import ServiceBrowser, Zeroconf

from .model.categories import Categories


class CollectingListener(object):
    """Listener for discovered services."""

    def __init__(self):
        """Initialize the object."""
        self.data = []

    def remove_service(self, zeroconf, type_, name):
        """
        Service was removed.

        This is ignored since we're not interested in disappearing services.

        :param zeroconf: the Zeroconf object associated with this listener
        :param type_: the service type
        :param name: the service name
        """
        pass

    def add_service(self, zeroconf, type_, name):
        """
        Service was added.

        :param zeroconf: the Zeroconf object associated with this listener
        :param type_: the service type
        :param name: the service name
        """
        info = zeroconf.get_service_info(type_, name)
        self.data.append(info)

    def get_data(self):
        """
        Get the list of discovered records.

        :returns: list of ServiceInfo records
        """
        return self.data


def discover_homekit_devices(timeout=1):
    """
    Search for HAP devices on the network.

    :returns: list of dicts containing service info
    """
    zeroconf = Zeroconf()
    listener = CollectingListener()
    browser = ServiceBrowser(zeroconf, '_hap._tcp.local.', listener)
    sleep(timeout)

    devices = []
    for info in listener.get_data():
        device = {
            'name': info.name,
            'address': inet_ntoa(info.address),
            'port': info.port,
            'c#': int(info.properties[b'c#'].decode()),
            'ff': int(info.properties[b'ff'].decode()),
            'id': info.properties[b'id'].decode(),
            'md': info.properties[b'md'].decode(),
            'pv': info.properties[b'pv'].decode(),
            's#': int(info.properties[b's#'].decode()),
            'sf': int(info.properties[b'sf'].decode()),
            'ci': Categories[int(info.properties[b'ci'].decode())],
        }
        devices.append(device)

    browser.cancel()
    zeroconf.close()
    return devices


def find_device_ip_and_port(device_id: str):
    """
    Find a specific device on the network.

    :param device_id: ID of device to search for
    :returns: dict containing IP and port, if found, else None
    """
    result = None
    zeroconf = Zeroconf()
    listener = CollectingListener()
    browser = ServiceBrowser(zeroconf, '_hap._tcp.local.', listener)
    counter = 0

    while result is None and counter < 10:
        sleep(1)
        data = listener.get_data()
        for info in data:
            if info.properties[b'id'].decode() == device_id:
                result = {'ip': inet_ntoa(info.address), 'port': info.port}
                break
        counter += 1

    browser.cancel()
    zeroconf.close()
    return result
