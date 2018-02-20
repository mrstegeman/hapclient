# HomeKit Python

With this code it is possible to implement a HomeKit Controller. This code was originally forked from: https://github.com/jlusiardi/homekit_python

**Limitations**

 * This code only works with HomeKit IP Accessories. no Bluetooth LE Accessories (yet)!
 * No reaction to events whatsoever.

The code presented in this repository was created based on release R1 from 2017-06-07.

# Installation

Use **pip3** to install the package:

```bash
pip3 install --user hapclient
```

# HomeKit Controller

To implement a simple HomeKit controller, you can do the following:

```python
from hapclient.client import HapClient
import json

# Find available devices.
devices = HapClient.discover()
print(json.dumps(devices, indent=2))

# Select a device
device = devices[0]

# Create a client
client = HapClient(device['id'],
                   address=device['address'],
                   port=device['port'])

# Pair with the device
pin = '123-45-678'  # replace this with your PIN
client.pair(pin)

# Print out the pairing data and save it somewhere, as you'll need it.
# The next time you create a HapClient, you won't be able to pair (since you've
# already done so, so instead, you'll pass in this dict as
# `pairing_data=<dict>`.
print(json.dumps(client.pairing_data, indent=2))

# List some things
print(json.dumps(client.get_accessories(), indent=2))
print(json.dumps(client.get_characteristics(['1.11']), indent=2))

# Set a characteristic
client.set_characteristics({'1.11': False})

# If you want to unpair, do the following:
client.unpair()
```

# Tests

The code was tested with the following devices:
* [iDevices Switch](https://store.idevicesinc.com/idevices-switch/)
* [Koogeek P1](https://www.koogeek.com/p-p1.html)
