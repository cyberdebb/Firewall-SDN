# --- App Ryu Parte 1 ---

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

SIMPLE_FIREWALL_INSTANCE_NAME = 'SimpleFirewall'

class FirewallAPIController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallAPIController, self).__init__(req, link, data, **config)
        self.firewall_app = data[SIMPLE_FIREWALL_INSTANCE_NAME]

    @route('firewall', '/firewall/rules', methods=['POST'])
    def post_rules(self, req):
        try:
            body = req.json if req.body else {}
            rules = body.get('rules', [])
            
            # Chama o método no app principal do Ryu para processar as regras
            self.firewall_app.update_mac_rules(rules)
            
            return Response(content_type='application/json', body=json.dumps({'status': 'Regras processadas pelo Ryu'}).encode('utf-8'))
        
        except Exception as e:
            logger = self.firewall_app.logger
            logger.error(f"Ocorreu um erro inesperado na API do Ryu: {e}")
            return Response(status=500, body=json.dumps({'error': str(e)}).encode('utf-8'))