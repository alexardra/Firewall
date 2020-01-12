#!/usr/bin/env python
from collections import namedtuple, defaultdict
import struct
import socket

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

from packets.ip import PacketIP
from packets.tcp import PacketTCP
from packets.udp import PacketUDP 
from packets.icmp import PacketICMP 

from rules.ip import IP
from rules.port import Port
from rules.domainname import Domainname

class PacketPermission:
    ALLOW = 1
    DENY = 2
    DROP = 3

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.country_code_map = self.__get_loaded_country_codes('geoipdb.txt')

        self.ProtocolRule = namedtuple(
            'ProtocolRule', ['verdict', 'protocol', 'ip', 'port'])
        self.DNSRule = namedtuple('DNSRule', ['verdict', 'domainname'])
        self.LogRule = namedtuple('LogRule', ['hostname'])

        self._dns_rules, self._http_rules, self._transport_rules = self.__get_loaded_rules(config['rule'])
        self._log_file = open('http.log', 'a+')

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        self.__log_packet(pkt_dir, pkt)

        unpacked_packet = PacketIP(pkt)
        if not unpacked_packet.is_valid():
            return

        permission = self.__allow_packet(unpacked_packet, pkt_dir)

        if permission == PacketPermission.ALLOW:
            self.__log_http_packets(unpacked_packet, pkt_dir)
            self.__send_packet(pkt, pkt_dir)
        elif permission == PacketPermission.DENY:
            reset_pkt = unpacked_packet.get_reset_packet()
            if not reset_pkt:
                return 

            sending_interface = PKT_DIR_INCOMING if unpacked_packet.get_protocol() == 'udp' else not pkt_dir
            self.__send_packet(reset_pkt, sending_interface)

    def __send_packet(self, pkt, pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def __get_match_ip_and_port(self, pkt, pkt_dir):
        ip = pkt.get_src_ip() if pkt_dir == PKT_DIR_INCOMING else pkt.get_dest_ip()

        upper_layer = pkt.get_upper_layer_packet()

        if pkt.get_protocol() == 'icmp':
            port = upper_layer.get_type()
        else:
            port = upper_layer.get_src_port() if pkt_dir == PKT_DIR_INCOMING else upper_layer.get_dest_port()

        return ip, port

    def __allow_packet(self, pkt, pkt_dir):
        if pkt.get_protocol() not in ['tcp', 'udp', 'icmp']:
            return PacketPermission.ALLOW

        ip_to_match, port_to_match = self.__get_match_ip_and_port(pkt, pkt_dir)
        
        return self.__get_verdict(pkt, ip_to_match, port_to_match)

    def __get_verdict(self, ip_pkt, ip, port):
        upper_layer_pkt = ip_pkt.get_upper_layer_packet()

        if ip_pkt.get_protocol() == 'udp' and upper_layer_pkt.is_valid_dns():
            for rule in self._dns_rules:
                if rule.domainname.is_match(upper_layer_pkt.get_dns_domain_name()):
                    return self.__get_packet_permision(rule.verdict)

        for rule in self._transport_rules:
            if ip_pkt.get_protocol() == rule.protocol and rule.ip.ip_in_network(ip) and rule.port.is_match(port):
                return self.__get_packet_permision(rule.verdict)
        
        return PacketPermission.ALLOW
        
    def __get_packet_permision(self, verdict):
        if verdict == 'deny':
            return PacketPermission.DENY
        
        if verdict == 'drop':
            return PacketPermission.DROP
        
        return PacketPermission.ALLOW

    def __log_http_packets(self, ip_packet, pkt_dir):
        if ip_packet.get_protocol() == 'tcp':
            upper_layer = ip_packet.get_upper_layer_packet()
            if upper_layer.is_http_to_log(pkt_dir == PKT_DIR_OUTGOING):
                for rule in self._http_rules:
                    if rule.hostname.is_match(upper_layer.get_http_hostname()):
                        log_msg = upper_layer.get_http_log_msg()
                        if log_msg:
                            self._log_file.write(upper_layer.get_http_log_msg() + '\n')
                            self._log_file.flush()
                        return                        

    def __get_loaded_rules(self, file_name):
        with open(file_name, 'r') as f:
            rules = f.read().splitlines()

        dns, http, transport = ([] for _ in xrange(3))

        for rule in rules:
            if len(rule) > 0 and not rule.startswith(('\n', '%')):
                rule_fields = map(lambda x: x.lower(), rule.split()[:4])

                try:
                    if rule_fields[1] == 'dns':
                        dns.append(self.DNSRule(verdict=rule_fields[0], domainname=Domainname(rule_fields[2])))
                    elif rule_fields[0] == 'log':
                        http.append(self.LogRule(hostname=Domainname(rule_fields[2])))
                    else:
                        verdict, protocol, ip, port = rule_fields
                        ip = IP(ip, self.country_code_map)
                        port = Port(port)
                        transport.append(self.ProtocolRule(verdict=verdict, protocol=protocol, ip=ip, port=port))
                except:
                    pass

        return dns, http, transport

    def __get_loaded_country_codes(self, file_name):
        with open(file_name, 'r') as f:
            codes = f.read().splitlines()

        IPRange = namedtuple('IPRange', ['start', 'end'])

        country_map = defaultdict(list)
        for line in map(lambda x: x.split(), codes):
            country_map[line[2].lower()].append(IPRange(line[0], line[1]))
        return country_map        

    def __log_packet(self, pkt_dir, pkt):
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)

        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                                                       socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
