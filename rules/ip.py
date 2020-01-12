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
        # print self._network

    def ip_in_network(self, ip):
        if type(self._network) == str: # next 5 lines from stack overflow 
            ipaddr = int(''.join(['%02x' % int(x) for x in ip.split('.')]), 16)
            netstr, bits = self._network.split('/')
            netaddr = int(''.join(['%02x' % int(x) for x in netstr.split('.')]), 16)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            return (ipaddr & mask) == (netaddr & mask)
         # IPRange

        return any([self.__ip_to_tuple(n.start) <= self.__ip_to_tuple(ip) <= self.__ip_to_tuple(n.end) for n in self._network])

    def __ip_to_tuple(self, ip):
        return tuple(int(n) for n in ip.split('.'))
