# --- App Ryu Parte 2: A Lógica Principal do Controlador ---
#
# ARQUITETURA:
# Este script é o coração do seu Plano de Controle. Ele é o aplicativo Ryu
# principal que gerencia os switches e o fluxo de tráfego. Ele tem duas
# responsabilidades distintas e complementares que trabalham em conjunto.
#
# RESPONSABILIDADE 1: FIREWALL REATIVO (Executor de Políticas)
# - Ele recebe ordens da sua API (através do método `update_mac_rules`).
# - Ele traduz essas ordens em regras OpenFlow de alta prioridade para
#   BLOQUEAR o tráfego malicioso diretamente nos switches.
#
# RESPONSABILIDADE 2: LEARNING SWITCH (Gerente de Tráfego Legítimo)
# - Para TODO o tráfego que NÃO é bloqueado, ele atua como um switch inteligente.
# - Ele aprende a localização dos dispositivos na rede (MACs e portas).
# - Ele instala regras de fluxo proativas para encaminhar o tráfego legítimo
#   de forma eficiente, sem precisar ser consultado a cada pacote.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.app.wsgi import WSGIApplication

# Importa o controlador da API e a constante do outro arquivo.
# Isso permite que o Ryu carregue os dois componentes juntos.
from firewall_api import FirewallAPIController, SIMPLE_FIREWALL_INSTANCE_NAME

class SimpleFirewall(app_manager.RyuApp):
    # Define a versão do protocolo OpenFlow que este aplicativo suporta.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Informa ao Ryu para carregar o contexto WSGI, que é o servidor web
    # necessário para rodar a nossa API interna.
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        # Tabela de aprendizado: armazena {dpid -> {mac: porta}}
        # É como o cérebro do switch sabe qual MAC está conectado em qual porta.
        self.mac_to_port = {}
        # Conjunto (set) para armazenar os MACs bloqueados. Usar um set é muito
        # mais rápido para verificar se um item existe do que usar uma lista.
        self.blocked_macs = set()
        # Dicionário para manter um registro de todos os switches (datapaths) conectados.
        self.datapaths = {}
        
        # --- Registro da API ---
        # Pega a instância do servidor web (wsgi) que o Ryu criou.
        wsgi = kwargs['wsgi']
        # Registra a nossa classe de API (FirewallAPIController), passando uma
        # referência a esta própria instância (self) para que a API possa
        # chamar os métodos deste aplicativo (como o update_mac_rules).
        wsgi.register(FirewallAPIController, {SIMPLE_FIREWALL_INSTANCE_NAME: self})
        self.logger.info("API do Firewall Ryu pronta em http://<ip_ryu>:8080/firewall/rules")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Este método é executado uma vez, logo que um switch se conecta ao controlador.
        É o momento de configurar o estado inicial do switch.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info(f"Switch conectado: {datapath.id:016x}")
        # Armazena o objeto datapath para uso futuro (ex: para aplicar novas regras).
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        # --- Instalação da Regra "Table-Miss" ---
        # Esta é a regra mais importante para o funcionamento do learning switch.
        # Ela diz ao switch: "Se você receber um pacote e não tiver NENHUMA outra
        # regra que corresponda a ele, não o descarte. Envie-o para mim (o controlador)".
        # Ela tem a menor prioridade (0), então só é usada como último recurso.
        match = parser.OFPMatch() # Um match vazio corresponde a qualquer pacote.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Se já tivermos regras de bloqueio, aplicamo-las a este novo switch.
        self._apply_block_rules_for_datapath(datapath)

    def add_flow(self, datapath, priority, match, actions):
        """
        Função auxiliar para simplificar a criação e envio de regras de fluxo (FlowMods).
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def update_mac_rules(self, rules):
        """
        Este método é chamado pela nossa API interna quando recebe uma ordem do firewall.
        É a ponte entre a decisão de segurança e a execução.
        """
        self.logger.info(f"Recebendo atualização de regras via API: {rules}")
        # Uma abordagem simples: apaga a lista antiga e recria com as novas regras.
        # Normaliza os MACs para minúsculas para evitar problemas de comparação.
        self.blocked_macs.clear()
        for rule in rules:
            mac = rule.get("mac")
            action = rule.get("action")
            if mac and action == "block":
                self.blocked_macs.add(mac.lower())
        
        self.logger.info(f"Lista de MACs bloqueados atualizada: {self.blocked_macs}")
        # Aplica as novas regras em TODOS os switches que estão conectados.
        for datapath in self.datapaths.values():
            self._apply_block_rules_for_datapath(datapath)

    def _apply_block_rules_for_datapath(self, datapath):
        """
        Instala as regras de bloqueio (DROP) para os MACs da lista `blocked_macs`.
        """
        parser = datapath.ofproto_parser
        # Uma lista de ações vazia em uma regra de fluxo significa "DROP" (descartar o pacote).
        actions = [] 
        self.logger.info(f"Aplicando regras de bloqueio no switch {datapath.id:016x}")
        for mac in self.blocked_macs:
            # Cria duas regras para cada MAC: uma para quando ele é a origem
            # e outra para quando ele é o destino.
            match_src = parser.OFPMatch(eth_src=mac)
            self.add_flow(datapath, 10, match_src, actions) # Prioridade alta (10) para garantir que seja verificada antes.
            
            match_dst = parser.OFPMatch(eth_dst=mac)
            self.add_flow(datapath, 10, match_dst, actions)
        self.logger.info(f"Regras de bloqueio aplicadas.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Este é o coração do "Learning Switch". Ele é executado para cada pacote
        que o switch não sabe o que fazer (devido à regra de table-miss).
        Sua função é lidar com o tráfego LEGÍTIMO.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] # Porta pela qual o pacote entrou.

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignora pacotes de protocolos de descoberta (LLDP) para não poluir os logs.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst.lower()
        src = eth.src.lower()
        dpid = datapath.id

        # 1. APRENDER: O controlador aprende que o MAC de origem (src) está na porta (in_port).
        # Ele guarda essa informação na sua "tabela de aprendizado".
        self.mac_to_port[dpid][src] = in_port

        # 2. VERIFICAR SEGURANÇA: Uma checagem extra. Se, por algum motivo, um pacote
        # de um MAC bloqueado chegar aqui, ele é descartado.
        if src in self.blocked_macs or dst in self.blocked_macs:
            self.logger.warning(f"PACOTE DESCARTADO (origem/destino bloqueado): {src} -> {dst}")
            return

        # 3. DECIDIR ROTA:
        # Se o MAC de destino já é conhecido (já aprendemos onde ele está)...
        if dst in self.mac_to_port[dpid]:
            # ...pegamos a porta de saída correta.
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            # E instalamos uma NOVA REGRA no switch para otimizar o tráfego futuro.
            # "Da próxima vez que vir um pacote de 'src' para 'dst', envie-o direto
            # para 'out_port', sem me perguntar de novo."
            # Prioridade 1: maior que table-miss (0), menor que bloqueio (10).
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
            
            # Envia o pacote atual que causou este evento para o seu destino.
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
        else:
            # Se o MAC de destino é desconhecido, a única opção é fazer "FLOOD":
            # enviar o pacote para todas as portas, exceto a que ele veio.
            # É como perguntar em voz alta: "Quem tem o MAC 'dst'?". O dispositivo
            # correto irá responder, e na resposta, o controlador aprenderá sua localização.
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
