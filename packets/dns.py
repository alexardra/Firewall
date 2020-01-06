import struct
import socket
import traceback
from packet import Packet

class PacketDNS(Packet):

    DNS_DENY_ADDR = '169.229.49.130'

    def __init__(self, pkt):
        self._packet = pkt
        self._is_valid_packet = False
        self.__unpack()

    def __unpack(self):
        self._header = struct.unpack_from('!6H', self._packet)
        qdcount = self._header[2]

        if qdcount != 1:
            return 

        self._qname, qname_offset = self.__get_qname_labels(12)
        self._raw_question = self._packet[12:qname_offset+4]        

        self._qtype, qclass = struct.unpack_from('!2H', self._packet[qname_offset:])

        if (self._qtype != 1 and self._qtype != 28) or qclass != 1:
            return 
        
        self._is_valid_packet = True

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

    def is_valid(self):
        return self._is_valid_packet

    def get_domainname(self):
        try:
            return self._qname
        except:
            print(traceback.format_exc()) 

    def get_reset_packet(self):
        if self._qtype != 1:
            return 

        request_flags = format(self._header[1], 'b').zfill(16)
        response_flags = int('1' + request_flags[1:-6] + '000000', 2)

        header_fields = [self._header[0], response_flags, self._header[2], 1, 0, 0]
        header = struct.pack('!6H', *header_fields)

        raw_qname = self._raw_question[:-4]
        answer = raw_qname + struct.pack('!2HIH', 1, 1, 1, 4) + \
            socket.inet_aton(PacketDNS.DNS_DENY_ADDR)

        return header + self._raw_question + answer