import struct
import socket
from packet import Packet

class PacketUDP(Packet):

    DNS_DENY_ADDR = '169.229.49.130'

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

                qname, new_offset = self.__get_qname_labels(qname_offset)
                self._raw_question = self._packet[qname_offset:new_offset + 2]
                qname_offset = new_offset

                qtype, qclass = struct.unpack_from(
                    '!2H', self._packet[qname_offset:])

                self._qname = qname
                self._qtype = qtype

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

    def get_qtype(self):
        try:
            return self._qtype
        except:
            return None

    def get_reset_packet(self):
        # print 'udp reset packet: '
        dns_header = struct.unpack_from(
            '!6H', self._packet[self._header_length:])

        request_flags = format(dns_header[1], 'b').zfill(16)
        response_flags = int('1' + request_flags[1:-4] + '0000', 2)

        header_fields = [dns_header[0], response_flags,
                         dns_header[2], 1, dns_header[4], dns_header[5]]
        header = struct.pack('!6H', *header_fields)

        question = self._raw_question

        qname = self._raw_question[:-4]
        answer = qname + struct.pack('!2HIH', 1, 1, 1, 4) + \
            socket.inet_aton(PacketUDP.DNS_DENY_ADDR)

        dns_response = header + question + answer

        length = 12 + len(dns_response)

        udp_header_fields = [self._dest_port, self._src_port, length, 0]
        udp_header_fields[3] = self.get_checksum(udp_header_fields)

        return struct.pack('!4H', *udp_header_fields) + dns_response