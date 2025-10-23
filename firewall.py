from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import IPAddr
import time

log = core.getLogger()

class SimpleDNSFirewall(EventMixin):
    
    def __init__(self):
        self.listenTo(core.openflow)
        
        self.blocked_domains = ['example.com', 'test.org']
        self.blocked_ips = set()
        
        log.info("Simple DNS Firewall started")

    def _handle_ConnectionUp(self, event):
        """When a switch connects"""
        log.info("Switch connected with DPID: %s", event.dpid)

    def _handle_PacketIn(self, event):
        """Process incoming packets"""
        packet = event.parsed
        if not packet.parsed:
            return

        # Check for DNS responses
        if hasattr(packet, 'find') and packet.find('dns'):
            self._process_dns(packet, event)
        
        # Block traffic to known bad IPs
        if hasattr(packet, 'find') and packet.find('ipv4'):
            ip_packet = packet.find('ipv4')
            if str(ip_packet.dstip) in self.blocked_ips:
                log.info("Blocking traffic to %s", ip_packet.dstip)
                # Don't install any actions = drop

    def _process_dns(self, packet, event):
        """Process DNS packets"""
        try:
            dns = packet.find('dns')
            if dns.qr:  # This is a response
                for answer in dns.answers:
                    if answer.type == 1:  # A record
                        domain = answer.name.rstrip('.')
                        ip = str(answer.rdata)
                        
                        # Check if domain should be blocked
                        for blocked in self.blocked_domains:
                            if blocked in domain:
                                self.blocked_ips.add(ip)
                                log.info("Blocked domain %s with IP %s", domain, ip)
                                break
        except Exception as e:
            log.error("DNS processing error: %s", e)

    def add_domain(self, domain):
        """Add domain to blocklist"""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            log.info("Added %s to blocklist", domain)

def launch():
    core.registerNew(SimpleDNSFirewall)
