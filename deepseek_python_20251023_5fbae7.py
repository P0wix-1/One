from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import IPAddr, EthAddr
import struct
import time

log = core.getLogger()

class DNSFirewall(EventMixin):
    """
    Firewall that blocks traffic based on domain names
    """
    
    def __init__(self):
        self.listenTo(core.openflow)
        
        # Список блокируемых доменов
        self.blocked_domains = [
            'example.com',
            'malicious-site.net', 
            'ads.google.com'
        ]
        
        # Кэш для хранения IP-адресов, соответствующих блокируемым доменам
        self.blocked_ips = set()
        
        # Временная метка последней очистки кэша
        self.last_cache_cleanup = time.time()
        
        log.info("DNS Firewall started")
        log.info("Blocked domains: %s", self.blocked_domains)

    def _handle_ConnectionUp(self, event):
        """Вызывается когда подключается новый свитч"""
        log.info("Switch %s connected", dpidToStr(event.dpid))
        
        # Устанавливаем правило для перенаправления DNS-трафика на контроллер
        self._add_dns_redirect_rule(event.connection)

    def _handle_PacketIn(self, event):
        """Обрабатывает входящие пакеты"""
        packet = event.parsed
        if not packet.parsed:
            return

        # Очищаем кэш каждые 5 минут
        if time.time() - self.last_cache_cleanup > 300:
            self._cleanup_cache()
            self.last_cache_cleanup = time.time()

        # Обрабатываем DNS-ответы
        if packet.find('dns'):
            self._handle_dns_response(packet, event)
        
        # Блокируем трафик на заблокированные IP-адреса
        if packet.find('ipv4'):
            ip_packet = packet.find('ipv4')
            dst_ip = ip_packet.dstip
            src_ip = ip_packet.srcip
            
            # Проверяем как исходный, так и целевой IP
            if str(dst_ip) in self.blocked_ips or str(src_ip) in self.blocked_ips:
                log.info("Blocking traffic to/from blocked IP: %s -> %s", src_ip, dst_ip)
                self._block_traffic(event.connection, packet, event.port)
                return

    def _handle_dns_response(self, packet, event):
        """Анализирует DNS-ответы и извлекает IP-адреса"""
        dns = packet.find('dns')
        ip_packet = packet.find('ipv4')
        
        if not dns or not ip_packet:
            return
            
        # Работаем только с ответами (не с запросами)
        if not dns.qr:
            return
            
        # Проверяем все ответы в DNS-пакете
        for answer in dns.answers:
            if answer.type == 1:  # A-record (IPv4)
                domain = answer.name.rstrip('.')  # Убираем точку в конце
                ip_address = answer.rdata
                
                # Проверяем, соответствует ли домен блокируемым
                if self._is_domain_blocked(domain):
                    log.info("Found blocked domain: %s -> %s", domain, ip_address)
                    self.blocked_ips.add(str(ip_address))
                    
                    # Немедленно блокируем этот IP
                    self._add_ip_block_rule(event.connection, ip_address)
                    
                    # Также блокируем обратный трафик
                    self._add_ip_block_rule(event.connection, ip_address, is_src=True)

    def _is_domain_blocked(self, domain):
        """Проверяет, должен ли домен быть заблокирован"""
        domain = domain.lower()
        for blocked_domain in self.blocked_domains:
            if blocked_domain.lower() in domain or domain.endswith('.' + blocked_domain.lower()):
                return True
        return False

    def _add_dns_redirect_rule(self, connection):
        """Добавляет правило для перенаправления DNS-трафика на контроллер"""
        # Правило для DNS-запросов (порт 53)
        match = of.ofp_match()
        match.dl_type = 0x0800  # IPv4
        match.nw_proto = 17     # UDP
        match.tp_dst = 53       # DNS
        
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg.priority = 100  # Высокий приоритет
        
        connection.send(msg)
        log.debug("DNS redirect rule installed")

    def _add_ip_block_rule(self, connection, ip_address, is_src=False):
        """Добавляет правило для блокировки IP-адреса"""
        match = of.ofp_match()
        match.dl_type = 0x0800  # IPv4
        
        if is_src:
            match.nw_src = IPAddr(ip_address)
        else:
            match.nw_dst = IPAddr(ip_address)
        
        msg = of.ofp_flow_mod()
        msg.match = match
        # Нет действий = пакет отбрасывается
        msg.priority = 200  # Очень высокий приоритет
        
        connection.send(msg)
        log.debug("Block rule added for IP: %s (src: %s)", ip_address, is_src)

    def _block_traffic(self, connection, packet, in_port):
        """Немедленно блокирует трафик"""
        # Создаем flow rule для блокировки этого конкретного потока
        if packet.find('ipv4'):
            ip_packet = packet.find('ipv4')
            
            match = of.ofp_match()
            match.dl_type = 0x0800
            match.nw_src = ip_packet.srcip
            match.nw_dst = ip_packet.dstip
            
            # Если это TCP/UDP, блокируем конкретные порты
            if packet.find('tcp'):
                tcp_packet = packet.find('tcp')
                match.nw_proto = 6
                match.tp_src = tcp_packet.srcport
                match.tp_dst = tcp_packet.dstport
            elif packet.find('udp'):
                udp_packet = packet.find('udp')
                match.nw_proto = 17
                match.tp_src = udp_packet.srcport
                match.tp_dst = udp_packet.dstport
            
            msg = of.ofp_flow_mod()
            msg.match = match
            # Нет действий = DROP
            msg.priority = 150
            msg.idle_timeout = 300  # Удалить правило через 5 минут без активности
            
            connection.send(msg)

    def _cleanup_cache(self):
        """Очищает устаревшие записи в кэше"""
        initial_size = len(self.blocked_ips)
        # В реальной реализации здесь была бы логика очистки старых записей
        log.debug("Cache cleanup: %d -> %d IPs blocked", initial_size, len(self.blocked_ips))

    def add_blocked_domain(self, domain):
        """Добавляет домен в список блокировки (можно вызывать динамически)"""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            log.info("Domain added to blocklist: %s", domain)
            
            # Очищаем кэш IP, чтобы перехватить новые DNS-запросы
            self.blocked_ips.clear()

    def remove_blocked_domain(self, domain):
        """Удаляет домен из списка блокировки"""
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
            log.info("Domain removed from blocklist: %s", domain)
            
            # Не очищаем сразу blocked_ips, так как IP могут быть общими
            # Они постепенно удалятся при cleanup

    def get_blocked_ips(self):
        """Возвращает список заблокированных IP-адресов"""
        return list(self.blocked_ips)

    def get_blocked_domains(self):
        """Возвращает список заблокированных доменов"""
        return self.blocked_domains[:]

def launch(blocked_domains=None):
    """
    Запуск DNS Firewall
    
    Использование в командной строке:
    ./pox.py dns_firewall --blocked=example.com,malicious-site.net
    """
    
    # Базовый список блокируемых доменов
    default_domains = [
        'example.com',
        'test-block.org'
    ]
    
    # Добавляем домены из аргументов командной строки
    if blocked_domains:
        if isinstance(blocked_domains, str):
            domains_list = [d.strip() for d in blocked_domains.split(',')]
            default_domains.extend(domains_list)
    
    # Создаем и регистрируем компонент
    firewall = DNSFirewall()
    firewall.blocked_domains = default_domains
    
    core.register("dns_firewall", firewall)