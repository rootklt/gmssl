import binascii
from math import ceil
from .utils import rotl

IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]


def sm3_ff_j(x, y, z, j):
    ret = 0
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret


def sm3_gg_j(x, y, z, j):
    ret = 0
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret


def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))


def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))


def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i * 4, (i + 1) * 4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))
                       ) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "{:08x}".format(w[j])
    w_1 = []
    for j in range(64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "{:08x}".format(w_1[j])

    a, b, c, d, e, f, g, h = v_i

    for j in range(64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
             e +
             (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x: x & 0xFFFFFFFF, [a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]


def sm3_hash(msg) -> bytes:  # sourcery skip: for-append-to-extend
    '''
    计算消息摘要
    :param msg bytes 消息
    :returns bytes  返回sm3哈希值，hex格式。
    '''
    len1 = len(msg)
    reserve1 = len1 % 64
    reserve1 = reserve1 + 1

    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end += 64

    msg += b'\x80' + b'\x00' * (range_end - reserve1)
    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for _ in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg += chr(bit_length_str[7-i]).encode()

    group_count = round(len(msg) / 64)

    B = [msg[i*64:(i+1)*64] for i in range(group_count)]
    V = [IV]
    for i in range(group_count):
        V.append(sm3_cf(V[i], B[i]))
    result = ""
    for i in V[i+1]: #type: ignore
        result = f'{result}{i:08x}'
    return result.encode()


def sm3_kdf(z: bytes, klen) -> bytes:  # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    rcnt = ceil(klen/32)
    zin = list(binascii.unhexlify(z))
    ha = b""
    for ct, _ in enumerate(range(rcnt), start=1):
        msg = zin + list(binascii.a2b_hex(('%08x' % ct).encode('utf8')))
        ha = ha + sm3_hash(bytes(msg))
    return ha[:klen * 2]
