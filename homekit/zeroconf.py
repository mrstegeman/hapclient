from socket import inet_ntoa
from time import sleep
from zeroconf import ServiceBrowser, Zeroconf

from .model.categories import Categories


class CollectingListener(object):
    def __init__(self):
        self.data = []

    def remove_service(self, zeroconf, type, name):
        # this is ignored since not interested in disappearing stuff
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        self.data.append(info)

    def get_data(self):
        return self.data


def discover_homekit_devices():
    zeroconf = Zeroconf()
    listener = CollectingListener()
    browser = ServiceBrowser(zeroconf, '_hap._tcp.local.', listener)
    sleep(1)

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
            'ci': int(info.properties[b'ci'].decode()),
        }
        devices.append(device)

    browser.cancel()
    zeroconf.close()
    return devices


def find_device_ip_and_port(device_id: str):
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
