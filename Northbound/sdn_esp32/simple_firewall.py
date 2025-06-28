# --- App Ryu Parte 2 ---

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.app.wsgi import WSGIApplication
from firewall_api import FirewallAPIController, SIMPLE_FIREWALL_INSTANCE_NAME

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        # Inicialização de mac_to_port, blocked_macs, datapaths, registro da API
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_macs = set()
        self.datapaths = {}
        wsgi = kwargs['wsgi']
        wsgi.register(FirewallAPIController, {SIMPLE_FIREWALL_INSTANCE_NAME: self})
        self.logger.info("API do Firewall Ryu pronta em http://<ip_ryu>:8080/firewall/rules")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Instala regra de table-miss e aplica regras de bloqueio existentes
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info(f"Switch conectado: {datapath.id:016x}")
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self._apply_block_rules_for_datapath(datapath)

    def add_flow(self, datapath, priority, match, actions):
        # Função auxiliar para adicionar regras de fluxo
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def update_mac_rules(self, rules):
        # Chamado pela API, atualiza o set de MACs bloqueados e aplica nos switches
        self.logger.info(f"Recebendo atualização de regras via API: {rules}")
        self.blocked_macs.clear()
        for rule in rules:
            mac = rule.get("mac")
            action = rule.get("action")
            if mac and action == "block":
                self.blocked_macs.add(mac.lower())
        self.logger.info(f"Lista de MACs bloqueados atualizada: {self.blocked_macs}")
        for datapath in self.datapaths.values():
            self._apply_block_rules_for_datapath(datapath)

    def _apply_block_rules_for_datapath(self, datapath):
        # Instala as regras de DROP para os MACs bloqueados
        parser = datapath.ofproto_parser
        actions = [] 
        self.logger.info(f"Aplicando regras de bloqueio no switch {datapath.id:016x}")
        for mac in self.blocked_macs:
            match = parser.OFPMatch(eth_src=mac)
            self.add_flow(datapath, 10, match, actions)
            match_dst = parser.OFPMatch(eth_dst=mac)
            self.add_flow(datapath, 10, match_dst, actions)
        self.logger.info(f"Regras de bloqueio aplicadas.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Coração do learning switch
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst.lower()
        src = eth.src.lower()
        dpid = datapath.id
        self.mac_to_port[dpid][src] = in_port
        if src in self.blocked_macs or dst in self.blocked_macs:
            self.logger.warning(f"PACOTE DESCARTADO (origem/destino bloqueado): {src} -> {dst}")
            return
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)