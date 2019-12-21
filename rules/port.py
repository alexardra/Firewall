from collections import namedtuple

class Port(object):
    PortRange = namedtuple('PortRange', ['start', 'end'])

    def __init__(self, port):
        self._port = port

        range = port.split('-')
        if len(range) > 1:
            self._port = Port.PortRange(start=range[0], end=range[1])

    def is_match(self, port):
        if self._port == 'any':
            return True

        try:
            return int(self._port) == int(port)
        except:
            return port >= int(self._port.start) and port <= int(self._port.end)