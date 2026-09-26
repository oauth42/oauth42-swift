"""Disposable TLS fixture: never connects to production or logs credentials."""
import http.server
import json
import ssl
import sys
import threading

hits = 0
mode = sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, value, status=200, headers=None):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global hits
        origin = 'https://' + self.headers['Host']
        if self.path == '/.well-known/openid-configuration':
            self.respond(dict(issuer=origin, authorization_endpoint=origin+'/authorize',
                token_endpoint=origin+'/token', jwks_uri=origin+'/jwks',
                response_types_supported=['code'], subject_types_supported=['public'],
                id_token_signing_alg_values_supported=['RS256'], code_challenge_methods_supported=['S256']))
        elif self.path == '/stats':
            self.respond({'redirect_hits': hits})
        else:
            hits += 1
            self.respond({})

    def do_POST(self):
        global hits
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.path == '/token':
            destination = server.server_port if mode == 'same' else sink.server_port
            self.respond({}, 307, {'Location': f'https://localhost:{destination}/stolen'})
        else:
            hits += 1
            self.respond({'access_token': 'leaked', 'token_type': 'Bearer', 'expires_in': 3600})

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
sink = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
for item in (server, sink):
    item.socket = context.wrap_socket(item.socket, server_side=True)
    threading.Thread(target=item.serve_forever, daemon=True).start()
print(server.server_port, flush=True)
sys.stdin.buffer.read()
server.shutdown()
sink.shutdown()
