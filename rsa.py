import os

#Converte bytes para inteiro grande
def _bytes_para_int(dados):
    return int.from_bytes(dados, 'big')


#Converte inteiro grande para bytes com tamanho fixo
def _int_para_bytes(numero, tamanho):
    return numero.to_bytes(tamanho, 'big')


#Exponenciação modular rapida
def _potencia_modular(base, expoente, modulo):
    resultado = 1
    base = base % modulo

    while expoente > 0:
        if expoente & 1:
            resultado = (resultado * base) % modulo

        base = (base * base) % modulo
        expoente >>= 1

    return resultado


#Teste de primalidade Miller-Rabin
def _miller_rabin(n):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    #Escreve n-1 como 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    #Testemunhas deterministas para numeros de ate 3317044064679887385961981
    testemunhas = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for a in testemunhas:
        if a >= n:
            continue

        x = _potencia_modular(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False

    return True


#Gera um primo aleatorio com o numero de bits informado
def _gerar_primo(bits):
    while True:
        numero = _bytes_para_int(os.urandom(bits // 8))
        numero |= (1 << (bits - 1))
        numero |= 1

        if _miller_rabin(numero):
            return numero


#Algoritmo de Euclides estendido
def _euclides_estendido(a, b):
    if b == 0:
        return a, 1, 0

    mdc, x1, y1 = _euclides_estendido(b, a % b)
    return mdc, y1, x1 - (a // b) * y1


#Calcula o inverso modular de a em relacao a m
def _inverso_modular(a, m):
    mdc, x, _ = _euclides_estendido(a % m, m)

    if mdc != 1:
        raise ValueError('nao existe')

    return x % m


#Padding
def _aplicar_padding(mensagem, tamanho_bloco):
    tamanho_ps = tamanho_bloco - len(mensagem) - 3

    if tamanho_ps < 8:
        raise ValueError('Mensagem mto grande')

    ps = bytearray()
    while len(ps) < tamanho_ps:
        byte = os.urandom(1)[0]
        if byte != 0:
            ps.append(byte)

    return b'\x00\x02' + bytes(ps) + b'\x00' + mensagem


#Remove o padding e retorna so a mensagem original
def _remover_padding(bloco):
    if bloco[0:2] != b'\x00\x02':
        raise ValueError('Padding invalido')

    indice = bloco.index(b'\x00', 2)
    return bloco[indice + 1:]


#Gera o par de chaves RSA
def gerar_chaves(bits=512):
    p = _gerar_primo(bits // 2)

    q = _gerar_primo(bits // 2)
    while q == p:
        q = _gerar_primo(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while _euclides_estendido(e, phi)[0] != 1:
        e += 2

    d = _inverso_modular(e, phi)

    chave_publica = (e, n)
    chave_privada = (d, n)
    return chave_publica, chave_privada


def cifrar_rsa(mensagem, chave_publica):
    e, n = chave_publica
    tamanho_n = (n.bit_length() + 7) // 8

    bloco = _aplicar_padding(mensagem, tamanho_n)
    m = _bytes_para_int(bloco)
    c = _potencia_modular(m, e, n)

    return _int_para_bytes(c, tamanho_n)


def decifrar_rsa(cifrado, chave_privada):
    d, n = chave_privada
    tamanho_n = (n.bit_length() + 7) // 8

    c = _bytes_para_int(cifrado)
    m = _potencia_modular(c, d, n)
    bloco = _int_para_bytes(m, tamanho_n)

    return _remover_padding(bloco)


#Converte (expoente, modulo) para string hex separada por : para envio HTTP
def serializar_chave(chave):
    expoente, modulo = chave
    return f'{expoente:x}:{modulo:x}'


def deserializar_chave(texto):
    partes = texto.split(':')
    return (int(partes[0], 16), int(partes[1], 16))
