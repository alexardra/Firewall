from collections import namedtuple
import traceback
from packet import Packet

class PacketHTTP(Packet):
    connections = {}

    HttpRequest = namedtuple('Request', ['host', 'method', 'path', 'version'])
    HttpResponse = namedtuple('Response', ['statuscode', 'size'])

    def __init__(self, pkt, src_pair, dest_pair, outgoing, seq):
        self._packet = pkt
        self._src_pair, self._dest_pair = src_pair, dest_pair
        self._is_transaction_assembled = False

        self._tcp_seq = seq

        self.__unpack(outgoing)

    def __unpack(self, outgoing):
        if outgoing:
            self.__unpack_request()
        else:
            self.__unpack_response()

    def __unpack_request(self):
        self._request = self.__get_request()

        endpoint_pairs = (self._src_pair, self._dest_pair)

        if self._request:
            PacketHTTP.connections[endpoint_pairs] = (self._request, {})
            return

        if not endpoint_pairs in PacketHTTP.connections:
            PacketHTTP.connections[endpoint_pairs] = ({ self._tcp_seq: self._request }, {} )
            return

        expected_seq = self.__get_last_seq_num(PacketHTTP.connections[endpoint_pairs][0])
        if expected_seq != -1 and self._tcp_seq >= expected_seq:
            return 

        packet = self.__assemble_existing_packets(PacketHTTP.connections[endpoint_pairs][0])

        self._request = self.__get_request(packet)
        
        if not self._request:
            PacketHTTP.connections[endpoint_pairs][0][self._tcp_seq] = self._packet 

    def __assemble_existing_packets(self, sequence_packet_map):
        sorted_packets = sorted(sequence_packet_map.items(), key=lambda x:x[0])
        return ''.join([packet[1] for packet in sequence_packet_map])

    def __get_last_seq_num(self, sequence_packet_map):
        try:
            return sorted(sequence_packet_map.items(), key=lambda x:x[0])[-1][0]
        except:
            return -1

    def __unpack_response(self):
        self._response = self.__get_response()

        endpoint_pairs = (self._dest_pair, self._src_pair)

        if not endpoint_pairs in PacketHTTP.connections:
            return 

        if self._response:
            self._request = PacketHTTP.connections[endpoint_pairs][0]
            del PacketHTTP.connections[endpoint_pairs]
            self._is_transaction_assembled = True

            return
        
        expected_seq = self.__get_last_seq_num(PacketHTTP.connections[endpoint_pairs][1])
        if expected_seq != -1 and self._tcp_seq >= expected_seq:
            return 

        packet = self.__assemble_existing_packets(PacketHTTP.connections[endpoint_pairs][1])

        self._response = self.__get_response(packet)
        if not self._response:
            PacketHTTP.connections[endpoint_pairs][1][self._tcp_seq] = self._packet 
            return
        
        self._request = PacketHTTP.connections[endpoint_pairs][0]
        del PacketHTTP.connections[endpoint_pairs]
        self._is_transaction_assembled = True

    def __get_request(self, packet=None):
        if not packet:
            packet = self._packet

        try:
            line, headers = self.__get_line_and_headers(packet)
            method, path, version = line.split(' ')
            host = self.__get_header_value(headers, 'host')

            if not host:
                host = self._dest_pair.ip

            return PacketHTTP.HttpRequest(host=host, method=method, path=path, version=version)
        except:
            print(traceback.format_exc())

    def __get_response(self, packet=None):
        if not packet:
            packet = self._packet

        try:
            line, headers = self.__get_line_and_headers(packet)
            status_code = line.split(' ')[1]

            size = self.__get_header_value(headers, 'content-length')
            if not size:
                size = '-1'

            return PacketHTTP.HttpResponse(size=size, statuscode=status_code)
        except:
            self._is_transaction_assembled = False

    def __get_line_and_headers(self, packet):
        line = packet.split('\r\n')[0]
        headers = packet[packet.index('\n') + 1:].lower()

        return line, headers

    def __get_header_value(self, headers, key):
        if key not in headers:
            return None
        index = headers.index(key)

        return headers[index: headers.index('\r\n', index)].split(' ')[1]

    def is_assembled(self):
        return self._is_transaction_assembled

    def get_log_msg(self):
        try:
            print self._request, self._response
            request = [self._request.host, self._request.method,
                       self._request.path, self._request.version]
            response = [self._response.statuscode, self._response.size]
            print request, response
            return ' '.join(request + response)
        except:
            print(traceback.format_exc())
