import traceback
import struct
import socket
from collections import namedtuple
from packet import PacketTransport
from http import PacketHTTP


class PacketTCP(PacketTransport):
    seq = -1

    AddressPair = namedtuple('AddressPair', ['ip', 'port'])

    def __init__(self, pkt, src_ip, dest_ip):
        PacketTransport.__init__(self, 'tcp')

        self._packet = pkt
        self._src_ip = src_ip
        self._dest_ip = dest_ip
        self.__unpack()

    def __unpack(self):
        self._src_port, self._dest_port, self._seq, _, offset = struct.unpack_from(
            '!HHIIB', self._packet)
        self._header_length = (offset >> 4) * 4

        self._src_pair = PacketTCP.AddressPair(self._src_ip, self._src_port)
        self._dest_pair = PacketTCP.AddressPair(self._dest_ip, self._dest_port)

    def get_src_port(self):
        return self._src_port

    def get_dest_port(self):
        return self._dest_port

    def is_http_to_log(self, outgoing):
        if not self._packet[self._header_length:]:  # if no tcp payload
            return False

        if (outgoing and self._dest_port != 80) or (not outgoing and self._src_port != 80):  # if not http
            return False

        self._upper_layer_packet = PacketHTTP(
            self._packet[self._header_length:], self._src_pair, self._dest_pair, outgoing, self._seq)

        return self._upper_layer_packet.is_assembled()

    def get_http_log_msg(self):
        msg = ''
        try:
            msg = self._upper_layer_packet.get_log_msg()
        except:
            print(traceback.format_exc())
        finally:
            return msg

    def get_reset_packet(self):
        header = self.__construct_header()
        pseudo_header = self.get_pseudo_header(self._dest_ip, self._src_ip, len(header))

        checksum = self.get_checksum(pseudo_header + header)
        checksum_header_index = 16

        return header[:checksum_header_index] + struct.pack('!H', checksum) + header[checksum_header_index + 2:]

    def __construct_header(self):
        PacketTCP.seq = (PacketTCP.seq + 1) % 4294967296
        hl_reset = struct.unpack('!H', bytearray([80, 4]))[0]
        window = socket.htons(5840)

        return struct.pack('!2H2L4H', self._dest_port, self._src_port, PacketTCP.seq, 0, hl_reset, window, 0, 0)
