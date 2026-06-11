import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from rsa import gerar_chaves
from protocolo import (
    TIPO_CHAVE, TIPO_MENSAGEM, TIPO_OK,
    montar_pacote_chave, montar_pacote_ok, montar_pacote_mensagem,
    decodificar_pacote, decifrar_mensagem, extrair_chave_publica
)


PORTA_A  = 8001
PORTA_B  = 8002
NOME     = 'A'
URL_B    = f'http://localhost:{PORTA_B}'

chave_publica    = None
chave_privada    = None
chave_publica_b  = None
handshake_ok     = threading.Event()


def fazer_post(url, corpo):
    dados = corpo.encode('utf-8')
    requisicao = Request(url, data=dados, method='POST')
    requisicao.add_header('Content-Type', 'application/json')
    urlopen(requisicao)


class ManipuladorA(BaseHTTPRequestHandler):

    def do_POST(self):
        global chave_publica_b

        tamanho = int(self.headers.get('Content-Length', 0))
        corpo = self.rfile.read(tamanho).decode('utf-8')
        pacote = decodificar_pacote(corpo)

        if self.path == '/handshake':
            chave_publica_b = extrair_chave_publica(pacote)
            print(f'[{NOME}] Chave publica de B recebida.')

            #Responde com a propria chave publica
            resposta = montar_pacote_chave(chave_publica)
            fazer_post(f'{URL_B}/handshake', resposta)

            handshake_ok.set()
            self._responder(montar_pacote_ok())

        elif self.path == '/mensagem':
            texto = decifrar_mensagem(pacote, chave_privada)
            print(f'\n[B] {texto}')
            print(f'[{NOME}] ', end='', flush=True)
            self._responder(montar_pacote_ok())

        else:
            self.send_response(404)
            self.end_headers()

    def _responder(self, corpo):
        dados = corpo.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(dados)))
        self.end_headers()
        self.wfile.write(dados)

    def log_message(self, format, *args):
        pass


def loop_envio():
    handshake_ok.wait()
    print(f'[{NOME}] Conexao concluida\n')

    while True:
        texto = input(f'[{NOME}] ')
        if texto.strip():
            pacote = montar_pacote_mensagem(texto, chave_publica_b)
            fazer_post(f'{URL_B}/mensagem', pacote)


def main():
    global chave_publica, chave_privada

    print(f'[{NOME}] Gerando chaves RSA...')
    chave_publica, chave_privada = gerar_chaves(bits=512)
    print(f'[{NOME}] Chaves geradas.')
    print(f'[{NOME}] Servidor HTTP em http://localhost:{PORTA_A}')
    print(f'[{NOME}] Aguardando conexao de B...\n')

    servidor = HTTPServer(('localhost', PORTA_A), ManipuladorA)
    thread_servidor = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread_servidor.start()

    try:
        loop_envio()
    except KeyboardInterrupt:
        print(f'\n[{NOME}] Encerrado.')
        servidor.shutdown()


if __name__ == '__main__':
    main()
