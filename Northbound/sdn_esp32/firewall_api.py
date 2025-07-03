# --- App Ryu Parte 1: O Ponto de Entrada da API Interna ---
#
# ARQUITETURA:
# Este script define a API REST que roda DENTRO do controlador Ryu. Ele é o ponto de
# entrada para ordens externas. Ele não contém a lógica de controle de switches,
# apenas a lógica para receber, validar e passar as ordens para o aplicativo
# principal do Ryu.
#
# RESPONSABILIDADES:
# 1. EXPOR UM ENDPOINT: Cria a rota HTTP (ex: /firewall/rules) que a API Northbound
#    (Flask) irá chamar.
# 2. RECEBER DADOS: Aceita requisições POST com o payload JSON contendo as regras.
# 3. DELEGAR A AÇÃO: Não processa as regras diretamente. Em vez disso, ele chama
#    um método no aplicativo Ryu principal (SimpleFirewall) para que ele execute a lógica.
#    Isso mantém o código organizado e desacoplado.

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

# Uma constante para evitar "magic strings". É o nome que o Ryu usa para
# identificar a instância do nosso aplicativo principal.
SIMPLE_FIREWALL_INSTANCE_NAME = 'SimpleFirewall'

class FirewallAPIController(ControllerBase):
    """
    Esta classe herda de ControllerBase do Ryu, o que a torna um componente
    web que pode ser registrado no servidor WSGI interno do Ryu.
    """
    def __init__(self, req, link, data, **config):
        super(FirewallAPIController, self).__init__(req, link, data, **config)
        # O Ryu passa um dicionário 'data' durante a inicialização.
        # Nós pegamos a instância do nosso aplicativo principal (SimpleFirewall)
        # a partir dele, para que possamos chamar seus métodos.
        self.firewall_app = data[SIMPLE_FIREWALL_INSTANCE_NAME]

    # A anotação @route é como o @app.route do Flask, mas para o Ryu.
    # Ela mapeia a URL /firewall/rules para o método post_rules quando a
    # requisição for do tipo POST.
    @route('firewall', '/firewall/rules', methods=['POST'])
    def post_rules(self, req):
        """
        Este método é executado quando a API Flask reenvia a regra.
        """
        try:
            # Extrai o corpo JSON da requisição.
            body = req.json if req.body else {}
            rules = body.get('rules', [])
            
            # ETAPA DE DELEGAÇÃO:
            # Aqui, a API não tenta entender as regras. Ela simplesmente chama
            # o método 'update_mac_rules' do nosso aplicativo principal (SimpleFirewall)
            # e passa a lista de regras para ele.
            self.firewall_app.update_mac_rules(rules)
            
            # Se a delegação for bem-sucedida, retorna uma resposta de sucesso (200 OK).
            # O .encode('utf-8') é crucial para converter a string JSON em bytes,
            # como esperado pela biblioteca webob do Ryu.
            return Response(content_type='application/json', body=json.dumps({'status': 'Regras processadas pelo Ryu'}).encode('utf-8'))
        
        except Exception as e:
            # Se qualquer erro ocorrer durante o processamento no aplicativo principal,
            # ele será capturado aqui.
            logger = self.firewall_app.logger
            logger.error(f"Ocorreu um erro inesperado na API do Ryu: {e}")
            # Retorna um erro 500 para a API Flask, que por sua vez o reportará.
            return Response(status=500, body=json.dumps({'error': str(e)}).encode('utf-8'))
