import struct
from packet import Packet

class PacketICMP(Packet):
    def __init__(self, pkt):
        self._packet = pkt
        self.__unpack()

    def __unpack(self):
        self._type = struct.unpack_from('!B', self._packet)[0]

    def get_type(self):
        return self._type
