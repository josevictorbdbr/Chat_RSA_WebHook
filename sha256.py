import struct

#Frações cubicas 64 primeiros primos
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

#Frações quadradas 8 primeiros primos
H_INICIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

MASCARA_32 = 0xFFFFFFFF


def rotacao(valor, n):
    return ((valor >> n) | (valor << (32 - n))) & MASCARA_32


def sigma_menor_1(x):
    return rotacao(x, 7) ^ rotacao(x, 18) ^ (x >> 3)


def sigma_menor_2(x):
    return rotacao(x, 17) ^ rotacao(x, 19) ^ (x >> 10)


def sigma_maior_1(x):
    return rotacao(x, 2) ^ rotacao(x, 13) ^ rotacao(x, 22)


def sigma_maior_2(x):
    return rotacao(x, 6) ^ rotacao(x, 11) ^ rotacao(x, 25)


def escolha(e, f, g):
    return (e & f) ^ (~e & g) & MASCARA_32


def maioria(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def _padding(mensagem: bytes) -> bytes:
    tamanho_bits = len(mensagem) * 8
    mensagem += b'\x80'

    #Preenche com zeros até 8 bytes antes de completar o bloco
    while len(mensagem) % 64 != 56:
        mensagem += b'\x00'

    #Tamanho original
    mensagem += struct.pack('>Q', tamanho_bits)
    return mensagem


def _comprimir(bloco: bytes, estado: list) -> list:
    
    #Expande o bloco para 64 palavras
    w = list(struct.unpack('>16I', bloco))

    for i in range(16, 64):
        s0 = sigma_menor_1(w[i - 15])
        s1 = sigma_menor_2(w[i - 2])
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASCARA_32)

    a, b, c, d, e, f, g, h = estado

    for i in range(64):
        t1 = (h + sigma_maior_2(e) + escolha(e, f, g) + K[i] + w[i]) & MASCARA_32
        t2 = (sigma_maior_1(a) + maioria(a, b, c)) & MASCARA_32

        h = g
        g = f
        f = e
        e = (d + t1) & MASCARA_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASCARA_32

    return [
        (estado[0] + a) & MASCARA_32,
        (estado[1] + b) & MASCARA_32,
        (estado[2] + c) & MASCARA_32,
        (estado[3] + d) & MASCARA_32,
        (estado[4] + e) & MASCARA_32,
        (estado[5] + f) & MASCARA_32,
        (estado[6] + g) & MASCARA_32,
        (estado[7] + h) & MASCARA_32,
    ]


def sha256(mensagem: bytes) -> bytes:
    dados = _padding(mensagem)
    estado = H_INICIAL[:]

    for i in range(0, len(dados), 64):
        estado = _comprimir(dados[i:i + 64], estado)

    return struct.pack('>8I', *estado)


def sha256_hex(mensagem: bytes) -> str:
    return sha256(mensagem).hex()