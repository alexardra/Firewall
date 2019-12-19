from collections import namedtuple

class IP(object):
    def __init__(self, network, country_code_map):
        self._network = network

        if self._network == 'any':
            self._network = '0.0.0.0/0'

        if len(self._network) == 2:
            # no need to check if entry exists
            self._network = country_code_map[self._network]

        if type(self._network) == str and len(self._network.split('/')) == 1:
            self._network += '/32'

    def ip_in_network(self, ip):
        if type(self._network) == str: # next 5 lines from stack overflow 
            ipaddr = int(''.join(['%02x' % int(x) for x in ip.split('.')]), 16)
            netstr, bits = self._network.split('/')
            netaddr = int(''.join(['%02x' % int(x) for x in netstr.split('.')]), 16)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            return (ipaddr & mask) == (netaddr & mask)
         # IPRange
        start_ip, end_ip = self._network.start_ip, self._network.end_ip
        return self.__ip_to_tuple(start_ip) < self.__ip_to_tuple(ip) < self.__ip_to_tuple(end_ip)

    def __ip_to_tuple(self, ip):
        return tuple(int(n) for n in ip.split('.'))


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


class Domainname(object):
    def __init__(self, domain):
        self._domain = domain

    def is_match(self, domainname):
        try:
            suffix = self._domain[self._domain.index('*') + 1:]
            return domainname.endswith(suffix)
        except:
            return domainname == self._domain
