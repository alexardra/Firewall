import socket
import struct

class Packet(object):
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

    MOD = 1 << 16

    def get_protocol_number(self, protocol):
        return Packet.protocol_map.keys()[Packet.protocol_map.values().index(protocol)]

    def get_protocol_txt(self, number):
        return Packet.protocol_map[number]

    def get_checksum(self, data):
        unpacked = struct.unpack('!{0}H'.format(len(data) / 2), data)
        sum = self.__ones_complement_add(unpacked[0], unpacked[1])

        for i in unpacked[2:]:
            sum = self.__ones_complement_add(sum, i)

        return self.__ones_complement(sum)

    def __ones_complement_add(self, a, b):
        res = a + b
        return res if res < Packet.MOD else (res + 1) % Packet.MOD

    def __ones_complement(self, n):
        return int(''.join('1' if x == '0' else '0' for x in bin(n)[2:].zfill(16)), 2)

class PacketTransport(Packet):

    def __init__(self, protocol):
        self._protocol = protocol

    def get_pseudo_header(self, src_ip, dest_ip, segment_length):
        src_addr = socket.inet_aton(src_ip)
        dest_addr = socket.inet_aton(dest_ip)
        protocol = self.get_protocol_number(self._protocol)

        return struct.pack('!4s4sBBH', src_addr, dest_addr, 0, protocol, segment_length)
