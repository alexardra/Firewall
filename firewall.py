#!/usr/bin/env python
from collections import namedtuple
import struct
import socket

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from packets import PacketIP, PacketTCP, PacketUDP, PacketICMP
from rulefields import IP, Port, Domainname


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.country_code_map = self.__get_loaded_country_codes('geoipdb.txt')

        self.ProtocolRule = namedtuple(
            'ProtocolRule', ['verdict', 'protocol', 'ip', 'port'])
        self.DNSRule = namedtuple('DNSRule', ['verdict', 'domainname'])

        self._rules = self.__get_loaded_rules(config['rule'])

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        self.__log_packet(pkt_dir, pkt)

        unpacked_packet = PacketIP(pkt)

        if not unpacked_packet.is_valid():
            return
	
        if self.__allow_packet(unpacked_packet, pkt_dir):
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

    def __allow_packet(self, pkt, pkt_dir):
        ip_to_match = pkt.get_src_ip(
        ) if pkt_dir == PKT_DIR_INCOMING else pkt.get_dest_ip()

        upper_layer = pkt.get_upper_layer_packet()

        if pkt.get_protocol() == 'udp' and upper_layer.is_valid_dns():
            return self.__get_dns_verdict(upper_layer, ip_to_match, pkt_dir)

        port_to_match = None

        if pkt.get_protocol() == 'tcp' or pkt.get_protocol() == 'udp':
            port_to_match = upper_layer.get_src_port(
            ) if pkt_dir == PKT_DIR_INCOMING else upper_layer.get_dest_port()
        elif pkt.get_protocol() == 'icmp':
            port_to_match = upper_layer.get_type()

        return self.__get_verdict(pkt.get_protocol(
        ), ip_to_match, port_to_match) if port_to_match else True

    def __get_verdict(self, protocol, ip, port):
        allow_packet = True

        for rule in self._rules:
            if type(rule) == self.ProtocolRule and rule.protocol == protocol:
                if rule.ip.ip_in_network(ip) and rule.port.is_match(port):
                    allow_packet = rule.verdict == 'pass'
        return allow_packet

    def __get_dns_verdict(self, packet, ip, pkt_dir):
        allow_packet = True

        port_to_match = packet.get_src_port(
        ) if pkt_dir == PKT_DIR_INCOMING else packet.get_dest_port()

        for rule in self._rules:
            if type(rule) == self.DNSRule:
                if rule.domainname.is_match(packet.get_dns_domain_name()):
                    allow_packet = rule.verdict == 'pass'
            elif rule.protocol == 'udp':
                if rule.ip.ip_in_network(ip) and rule.port.is_match(port_to_match):
                    allow_packet = rule.verdict == 'pass'
        return allow_packet

    def __get_loaded_rules(self, file_name):
        with open(file_name, 'r') as f:
            rules = f.read().splitlines()

        parsed_rules = []
        for rule in rules:
            if len(rule) > 0 and not rule.startswith(('\n', '%')):
                rule_fields = map(lambda x: x.lower(), rule.split()[:4])

                if rule_fields[1] == 'dns':
                    parsed_rules.append(self.DNSRule(
                        verdict=rule_fields[0], domainname=Domainname(rule_fields[2])))
                else:
                    verdict, protocol, ip, port = rule_fields
                    parsed_rules.append(self.ProtocolRule(
                        verdict=verdict, protocol=protocol, ip=IP(ip, self.country_code_map), port=Port(port)))

        return parsed_rules

    def __get_loaded_country_codes(self, file_name):
        with open(file_name, 'r') as f:
            codes = f.read().splitlines()

        IPRange = namedtuple('IPRange', ['start_ip', 'end_ip'])
        country_code_map = {}
        for line in codes:
            line = line.split()
            country_code_map[line[2].lower()] = IPRange(line[0], line[1])

        return country_code_map

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
