import traceback
import struct
import socket
from packet import Packet
from tcp import PacketTCP
from udp import PacketUDP
from icmp import PacketICMP


class PacketIP(Packet):

    def __init__(self, pkt):
        self._packet = pkt
        self._is_valid_packet = False
        self.__unpack()

    def __unpack(self):
        try:
            self._header_length = 4 * (ord(self._packet[0]) & 0xf)

            self._is_valid_packet = self._header_length >= 20

            if not self._is_valid_packet:
                return

            header_fields = struct.unpack_from('!B3H2BH4s4s', self._packet[1:])

            self._is_valid_packet = header_fields[1] == len(self._packet)
            if not self._is_valid_packet:
                return

            self._id = header_fields[2]
            self._fragment = header_fields[3]
            self._ttl = header_fields[4]
            self._protocol = self.get_protocol_txt(header_fields[5])
            self._src_ip = socket.inet_ntoa(header_fields[7])
            self._dest_ip = socket.inet_ntoa(header_fields[8])

            self.__unpack_upper_layer()
        except:
            print(traceback.format_exc())

    def __unpack_upper_layer(self):
        upper_layer = self._packet[self._header_length:]
        self._upper_layer_packet = None

        if self._protocol == 'tcp':
            self._upper_layer_packet = PacketTCP(
                upper_layer, self._src_ip, self._dest_ip)
        elif self._protocol == 'udp':
            self._upper_layer_packet = PacketUDP(upper_layer, self._src_ip, self._dest_ip)
        elif self._protocol == 'icmp':
            self._upper_layer_packet = PacketICMP(upper_layer)

    def get_header_length(self):
        return self._header_length

    def get_src_ip(self):
        return self._src_ip

    def get_dest_ip(self):
        return self._dest_ip

    def get_protocol(self):
        return self._protocol

    def get_upper_layer_packet(self):
        return self._upper_layer_packet

    def is_valid(self):
        return self._is_valid_packet

    def get_reset_packet(self):
        try:
            upper_layer = self._upper_layer_packet.get_reset_packet()
            if not upper_layer:
                return 

            header = self.__construct_header(len(upper_layer))
            checksum = self.get_checksum(header)

            checksum_header_index = 10
            header = header[:checksum_header_index] + struct.pack('!H', checksum) + header[checksum_header_index+2:]

            return header + upper_layer
        except:
            print(traceback.format_exc()) 

    def __construct_header(self, upper_layer_length):
        version_hl = 69
        tos = 0
        total_length = 20 + upper_layer_length
        protocol = self.get_protocol_number(self._protocol)
        ttl_protocol = struct.unpack('!H', bytearray([self._ttl, protocol]))[0]

        src_ip = socket.inet_aton(self._dest_ip)
        dest_ip = socket.inet_aton(self._src_ip)

        return struct.pack('!BBHHHHH4s4s', version_hl, tos, total_length, self._id, self._fragment, ttl_protocol, 0, src_ip, dest_ip)