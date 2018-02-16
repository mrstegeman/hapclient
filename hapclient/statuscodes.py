"""Definition of HAP status codes."""


class _HapStatusCodes(object):
    """This data is taken from Table 5-12 HAP Satus Codes on page 80."""

    INSUFFICIENT_PRIVILEGES = -70401

    def __init__(self):
        """Initialize the object."""
        self._codes = {
            0: 'This specifies a success for the request.',
            -70401: 'Request denied due to insufficient privileges.',
            -70402: 'Unable to communicate with requested service, e.g. the '
                    'power to the accessory was turned off.',
            -70403: 'Resource is busy, try again.',
            -70404: 'Cannot write to read only characteristic.',
            -70405: 'Cannot read from a write only characteristic.',
            -70406: 'Notification is not supported for characteristic.',
            -70407: 'Out of resources to process request.',
            -70408: 'Operation timed out.',
            -70409: 'Resource does not exist.',
            -70410: 'Accessory received an invalid value in a write request.',
            -70411: 'Insufficient Authorization.'
        }

        self._categories_rev = {self._codes[k]: k for k in self._codes.keys()}

    def __getitem__(self, item):
        if item in self._codes:
            return self._codes[item]

        raise KeyError('Item {item} not found'.format_map(item=item))


HapStatusCodes = _HapStatusCodes()
