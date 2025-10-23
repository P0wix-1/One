from pox.core import core
from pox.lib.addresses import IPAddr
import json

log = core.getLogger()

class FirewallManager(EventMixin):
    def __init__(self):
        self.firewall = core.dns_firewall
        
    def add_domain(self, domain):
        """Добавить домен в черный список"""
        self.firewall.add_blocked_domain(domain)
        return f"Domain {domain} added to blocklist"
    
    def remove_domain(self, domain):
        """Удалить домен из черного списка"""
        self.firewall.remove_blocked_domain(domain)
        return f"Domain {domain} removed from blocklist"
    
    def get_status(self):
        """Получить текущий статус"""
        return {
            'blocked_domains': self.firewall.get_blocked_domains(),
            'blocked_ips': self.firewall.get_blocked_ips()
        }

def launch():
    # Ждем инициализации основного firewall
    def start_manager():
        manager = FirewallManager()
        core.register("firewall_manager", manager)
        log.info("Firewall Manager started")
    
    core.call_when_ready(start_manager, "dns_firewall")