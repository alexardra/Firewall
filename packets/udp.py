import struct
import socket
import traceback
from packet import Packet
from packet import PacketTransport
from dns import PacketDNS

class PacketUDP(PacketTransport):

    def __init__(self, pkt, src_ip, dest_ip):
        PacketTransport.__init__(self, 'udp')

        self._packet = pkt
        self._src_ip = src_ip
        self._dest_ip = dest_ip
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
        if self._dest_port != 53:
            return False
        
        self._upper_layer_packet = PacketDNS(self._packet[self._header_length:])
        return self._upper_layer_packet.is_valid()

    def get_dns_domain_name(self):
        try:
            return self._upper_layer_packet.get_domainname()
        except:
            print(traceback.format_exc()) 

    def get_reset_packet(self):
        dns_packet = self._upper_layer_packet.get_reset_packet()
        if not dns_packet:
            return 

        header = struct.pack('!4H', self._dest_port, self._src_port, self._header_length + len(dns_packet), 0)

        pseudo_header = self.get_pseudo_header(self._dest_ip, self._src_ip, len(header) + len(dns_packet))
        
        udp_checksum_data = pseudo_header + header + dns_packet
        if len(udp_checksum_data) % 2 != 0:
            udp_checksum_data += '\x00'
 
        checksum = self.get_checksum(pseudo_header + header + dns_packet)
        checksum_header_index = 6

        header = header[:checksum_header_index] + struct.pack('!H', checksum) + header[checksum_header_index + 2:]

        return header + dns_packet