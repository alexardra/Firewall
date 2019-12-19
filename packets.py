import socket
import struct


class PacketIP(object):
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

    def __init__(self, pkt):
        self._packet = pkt
        self._is_valid_packet = True
        self.__unpack()

    def __unpack(self):
        try:
            self._header_length = 4 * (ord(self._packet[0]) & 0xf)

            self._is_valid_packet = self._header_length >= 20

            if self._is_valid_packet:
                header_fields = struct.unpack_from(
                    '!B3H2BH4s4s', self._packet[1:])

                total_length = header_fields[1]
                self._is_valid_packet = total_length == len(self._packet)

                if self._is_valid_packet:
                    self._protocol = PacketIP.protocol_map[header_fields[5]]
                    self._src_ip = socket.inet_ntoa(header_fields[7])
                    self._dest_ip = socket.inet_ntoa(header_fields[8])

                    self.__unpack_upper_layer()
        except:
            self._is_valid_packet = False

    def __unpack_upper_layer(self):
        upper_layer = self._packet[self._header_length:]
        self._upper_layer_packet = None

        if self._protocol == 'tcp':
            self._upper_layer_packet = PacketTCP(upper_layer)
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


class PacketTCP(object):
    def __init__(self, pkt):
        self._packet = pkt
        self.__unpack()

    def __unpack(self):
        self._src_port, self._dest_port = struct.unpack_from(
            '!HH', self._packet)

    def get_src_port(self):
        return self._src_port

    def get_dest_port(self):
        return self._dest_port


class PacketUDP(object):
    def __init__(self, pkt):
        self._packet = pkt
        self._header_length = 8
        self.__unpack()

    def __unpack(self):
        self._src_port, self._dest_port = struct.unpack_from(
            '!2H', self._packet)

    def get_src_port(self):
        return self._src_port

    def get_dest_port(self):
        return self._dest_port

    def is_valid_dns(self):
        if self._dest_port == 53:
            dns_header = struct.unpack_from(
                '!6H', self._packet[self._header_length:])
            qdcount = dns_header[2]

            if qdcount == 1:
                qname_offset = self._header_length + 12  # dns header length

                qname, qname_offset = self.__get_qname_labels(qname_offset)

                qtype, qclass = struct.unpack_from(
                    '!2H', self._packet[qname_offset:])

                self._qname = qname

                if (qtype == 1 or qtype == 28) and qclass == 1:
                    return True

        return False

    def get_dns_domain_name(self):
        try:
            return self._qname
        except:
            return None

    def __get_qname_labels(self, offset): 
        labels = ''

        while True:
            length = struct.unpack_from('!B', self._packet, offset)[0]

            if length == 0:
                offset += 1
                break

            if length > 63:
                pointer = struct.unpack_from(
                    '!H', self._packet, offset)[0]
                offset += 2
                continue

            offset += 1

            format = '!' + str(length) + 's'
            labels += struct.unpack_from(format,
                                         self._packet, offset)[0].decode() + '.'
            offset += length

        return labels[:-1], offset


class PacketICMP(object):
    def __init__(self, pkt):
        self._packet = pkt
        self.__unpack()

    def __unpack(self):
        self._type = struct.unpack_from('!B', self._packet)[0]

    def get_type(self):
        return self._type
