import json
from rsa import cifrar_rsa, decifrar_rsa, serializar_chave, deserializar_chave
from sha256 import sha256_hex


TIPO_CHAVE    = 'CHAVE_PUBLICA'
TIPO_MENSAGEM = 'MENSAGEM'
TIPO_OK       = 'OK'

_ALFABETO = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


#Converte bytes para string base64
def _b64_encode(dados):
    bits = 0
    acumulado = 0
    resultado = []

    for byte in dados:
        acumulado = (acumulado << 8) | byte
        bits += 8

        while bits >= 6:
            bits -= 6
            resultado.append(_ALFABETO[(acumulado >> bits) & 0x3F])

    #Padding de alinhamento
    if bits > 0:
        resultado.append(_ALFABETO[(acumulado << (6 - bits)) & 0x3F])

    while len(resultado) % 4 != 0:
        resultado.append('=')

    return ''.join(resultado)


#Converte string base64 de volta para bytes
def _b64_decode(texto):
    tabela = {c: i for i, c in enumerate(_ALFABETO)}

    #Remove padding
    texto = texto.rstrip('=')

    bits = 0
    acumulado = 0
    resultado = bytearray()

    for caractere in texto:
        acumulado = (acumulado << 6) | tabela[caractere]
        bits += 6

        if bits >= 8:
            bits -= 8
            resultado.append((acumulado >> bits) & 0xFF)

    return bytes(resultado)


def montar_pacote_chave(chave_publica):
    return json.dumps({
        'tipo': TIPO_CHAVE,
        'chave': serializar_chave(chave_publica)
    })


def montar_pacote_ok():
    return json.dumps({'tipo': TIPO_OK})


def montar_pacote_mensagem(texto, chave_publica_destino):
    hash_mensagem = sha256_hex(texto.encode('utf-8'))

    cifrado = cifrar_rsa(texto.encode('utf-8'), chave_publica_destino)
    dados_b64 = _b64_encode(cifrado)

    return json.dumps({
        'tipo': TIPO_MENSAGEM,
        'dados': dados_b64,
        'hash': hash_mensagem
    })


def decodificar_pacote(raw):
    return json.loads(raw)


def decifrar_mensagem(pacote, chave_privada):
    cifrado = _b64_decode(pacote['dados'])

    texto = decifrar_rsa(cifrado, chave_privada).decode('utf-8')

    hash_recebido = pacote['hash']
    hash_calculado = sha256_hex(texto.encode('utf-8'))

    if hash_recebido != hash_calculado:
        raise ValueError('Integridade comprometida')

    return texto


def extrair_chave_publica(pacote):
    return deserializar_chave(pacote['chave'])