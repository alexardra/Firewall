import traceback
import struct
from collections import namedtuple
from packet import Packet
from http import PacketHTTP


class PacketTCP(Packet):
    seq = -1

    AddressPair = namedtuple('AddressPair', ['ip', 'port'])

    def __init__(self, pkt, src_ip, dest_ip):
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
        if not self._packet[self._header_length:]: # if no tcp payload 
            return False

        if (outgoing and self._dest_port != 80) or (not outgoing and self._src_port != 80): # if not http
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
        PacketTCP.seq = (PacketTCP.seq + 1) % 4294967296
        seq = struct.unpack('!2H', struct.pack('!I', PacketTCP.seq))
        ack = struct.unpack('!2H', struct.pack('!I', self._seq))

        hl_reset = struct.unpack('!H', bytearray([80, 4]))[0]

        header_fields = [self._dest_port, self._src_port,
                         seq[0], seq[1], ack[0], ack[1], hl_reset, 65536, 0, 0]
        header_fields[7] = self.get_checksum(header_fields)
        header = struct.pack('!10H', *header_fields)

        return header
