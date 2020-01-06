#!/usr/bin/env python
from collections import namedtuple
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

        self._rules = self.__get_loaded_rules(config['rule'])

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
            self.__send_packet(pkt, pkt_dir)
        elif permission == PacketPermission.DENY:
            reset_pkt = unpacked_packet.get_reset_packet()
            if not reset_pkt:
                return 

            sending_interface = not pkt_dir
            if unpacked_packet.get_protocol() == 'udp':
                sending_interface = PKT_DIR_INCOMING

            self.__send_packet(reset_pkt, sending_interface)
                    

    def __send_packet(self, pkt, pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def __allow_packet(self, pkt, pkt_dir):
        if pkt.get_protocol() not in ['tcp', 'udp', 'icmp']:
            return PacketPermission.ALLOW
            
        ip_to_match = pkt.get_src_ip() if pkt_dir == PKT_DIR_INCOMING else pkt.get_dest_ip()

        upper_layer = pkt.get_upper_layer_packet()

        if pkt.get_protocol() == 'udp' and upper_layer.is_valid_dns():
            return self.__get_dns_verdict(upper_layer, ip_to_match, pkt_dir)

        port_to_match = None

        if pkt.get_protocol() == 'tcp' or pkt.get_protocol() == 'udp':
            port_to_match = upper_layer.get_src_port(
            ) if pkt_dir == PKT_DIR_INCOMING else upper_layer.get_dest_port()
        elif pkt.get_protocol() == 'icmp':
            port_to_match = upper_layer.get_type()

        verdict = self.__get_verdict(pkt.get_protocol(), ip_to_match, port_to_match)
        return verdict if port_to_match else PacketPermission.ALLOW

    def __get_verdict(self, protocol, ip, port):
        allow = True
        deny = False

        for rule in self._rules:
            if type(rule) == self.ProtocolRule and rule.protocol == protocol:
                if rule.ip.ip_in_network(ip) and rule.port.is_match(port):
                    allow = rule.verdict == 'pass'
                    deny = rule.verdict == 'deny'

        if deny:
            return PacketPermission.DENY
        
        if allow:
            return PacketPermission.ALLOW
        
        return PacketPermission.DROP

    def __get_dns_verdict(self, packet, ip, pkt_dir):
        allow = True
        deny = False

        port_to_match = packet.get_src_port(
        ) if pkt_dir == PKT_DIR_INCOMING else packet.get_dest_port()

        for rule in self._rules:
            if type(rule) == self.DNSRule:
                if rule.domainname.is_match(packet.get_dns_domain_name()):
                    allow = rule.verdict == 'pass'
                    deny = rule.verdict == 'deny'
            elif type(rule) == self.ProtocolRule and rule.protocol == 'udp':
                if rule.ip.ip_in_network(ip) and rule.port.is_match(port_to_match):
                    allow = rule.verdict == 'pass'
                    deny = rule.verdict == 'deny'
 
        if deny:
            return PacketPermission.DENY
        
        if allow:
            return PacketPermission.ALLOW
        
        return PacketPermission.DROP

    def __log_http_packets(self, ip_packet, pkt_dir):
        log = False
    
        if ip_packet.get_protocol() == 'tcp':

            for rule in self._rules:
                if type(rule) == self.LogRule:
                    pass
                    # log on hostname condition here

            upper_layer = ip_packet.get_upper_layer_packet()
            if upper_layer.is_http_to_log(pkt_dir == PKT_DIR_OUTGOING):
                self._log_file.write(upper_layer.get_http_log_msg() + '\n')
                self._log_file.flush()

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
                elif rule_fields[0] == 'log':
                    parsed_rules.append(self.LogRule(
                        hostname=Domainname(rule_fields[2])))
                else:
                    verdict, protocol, ip, port = rule_fields
                    parsed_rules.append(self.ProtocolRule(
                        verdict=verdict, protocol=protocol, ip=IP(ip, self.country_code_map), port=Port(port)))

        return parsed_rules

    def __get_loaded_country_codes(self, file_name):
        with open(file_name, 'r') as f:
            codes = f.read().splitlines()

        IPRange = namedtuple('IPRange', ['start_ip', 'end_ip'])
        return dict([(line[2].lower(), IPRange(line[0], line[1])) for line in map(lambda x: x.split(), codes)])

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

# Firewall({ 'rule': 'rules.conf' }, 0, 1)