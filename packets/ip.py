import traceback
import struct 
import socket
from packet import Packet
from tcp import PacketTCP
from udp import PacketUDP
from icmp import PacketICMP

class PacketIP(Packet):
    protocol_map = {
        1: 'icmp',
        2: 'igmp',
        6: 'tcp',
        9: 'igrp',
        17: 'udp',
        47: 'gre',
        50: 'esp',
        51: 'ah',
        57: 'skip',
        88: 'eigrp',
        89: 'ospf',
        115: 'l2tp',
    }

    id = -1

    def __init__(self, pkt):
        self._packet = pkt
        self._is_valid_packet = True
        self.__unpack()

    def __unpack(self):
        try:
            self._header_length = 4 * (ord(self._packet[0]) & 0xf)

            self._is_valid_packet = self._header_length >= 20

            if self._is_valid_packet:
                tos, total_length, id, fragment, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack_from(
                    '!B3H2BH4s4s', self._packet[1:])

                header_fields = struct.unpack_from(
                    '!B3H2BH4s4s', self._packet[1:])

                self._fragment = fragment
                self._ttl = ttl

                self._is_valid_packet = total_length == len(self._packet)

                if self._is_valid_packet:
                    self._protocol = PacketIP.protocol_map[header_fields[5]]
                    self._src_ip = socket.inet_ntoa(header_fields[7])
                    self._dest_ip = socket.inet_ntoa(header_fields[8])

                    self.__unpack_upper_layer()
        except:
            print(traceback.format_exc())
            self._is_valid_packet = False

    def __unpack_upper_layer(self):
        upper_layer = self._packet[self._header_length:]
        self._upper_layer_packet = None

        if self._protocol == 'tcp':
            self._upper_layer_packet = PacketTCP(
                upper_layer, self._src_ip, self._dest_ip)
        elif self._protocol == 'udp':
            self._upper_layer_packet = PacketUDP(upper_layer)
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
        PacketIP.id = (PacketIP.id + 1) % 65536

        src_ip = socket.inet_aton(self._dest_ip)
        dest_ip = socket.inet_aton(self._src_ip)

        src = struct.unpack('!2H', src_ip)
        dest = struct.unpack('!2H', dest_ip)

        v_hl_tos = struct.unpack('!H', bytearray([4, 5]))[0]
        ttl_protocol = struct.unpack('!H', bytearray([self._ttl, 6]))[0]

        header_fields = [v_hl_tos, 40, PacketIP.id, self._fragment,
                         ttl_protocol, 0, src[0], src[1], dest[0], dest[1]]
        header_fields[5] = self.get_checksum(header_fields)

        header = struct.pack('!10H', *header_fields)

        return header + self._upper_layer_packet.get_reset_packet()
