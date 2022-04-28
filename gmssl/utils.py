#!/usr/bin/env python3
# coding:utf-8

import gmpy2
from random import choice
from binascii import unhexlify


def multiply(a, n, N, A, P):
    return fromJacobian(jacobianMultiply(toJacobian(a), n, N, A, P), P)


def add(a, b, A, P):
    return fromJacobian(jacobianAdd(toJacobian(a), toJacobian(b), A, P), P)


def toJacobian(Xp_Yp):
    Xp, Yp = Xp_Yp
    return (Xp, Yp, 1)


def fromJacobian(Xp_Yp_Zp, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    z = gmpy2.invert(Zp, P)
    return ((Xp * z**2) % P, (Yp * z**3) % P)


def jacobianDouble(Xp_Yp_Zp, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    if not Yp:
        return (0, 0, 0)
    ysq = (Yp ** 2) % P
    S = (4 * Xp * ysq) % P
    M = (3 * Xp ** 2 + A * Zp ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * Yp * Zp) % P
    return (nx, ny, nz)


def jacobianAdd(Xp_Yp_Zp, Xq_Yq_Zq, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    Xq, Yq, Zq = Xq_Yq_Zq
    if not Yp:
        return (Xq, Yq, Zq)
    if not Yq:
        return (Xp, Yp, Zp)
    U1 = (Xp * Zq ** 2) % P
    U2 = (Xq * Zp ** 2) % P
    S1 = (Yp * Zq ** 3) % P
    S2 = (Yq * Zp ** 3) % P
    if U1 == U2:
        return (0, 0, 1) if S1 != S2 else jacobianDouble((Xp, Yp, Zp), A, P)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * Zp * Zq) % P
    return (nx, ny, nz)


def jacobianMultiply(Xp_Yp_Zp, n, N, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    if Yp == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return (Xp, Yp, Zp)
    if n < 0 or n >= N:
        return jacobianMultiply((Xp, Yp, Zp), n % N, N, A, P)
    if (n % 2) == 0:
        return jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P)
    if (n % 2) == 1:
        return jacobianAdd(jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P), (Xp, Yp, Zp), A, P)


def xor(a, b): return list(map(lambda x, y: x ^ y, a, b))


def rotl(x, n): return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


def get_uint32_be(key_data): return ((key_data[0] << 24) | (
    key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))


def put_uint32_be(n): return [((n >> 24) & 0xff), ((
    n >> 16) & 0xff), ((n >> 8) & 0xff), ((n) & 0xff)]


def padding(data, block=16): return data + bytes(16 - len(data) %
                                                 block for _ in range(16 - len(data) % block))


def unpadding(data): return data[:-data[-1]]


def list_to_bytes(data): return b''.join([bytes((i,)) for i in data])


def bytes_to_list(data): return list(data)


def random_hex(x): return ''.join(
    [choice('0123456789abcdef') for _ in range(x)]).encode()


int_from_bytes = lambda data, order = 'big': int.from_bytes(
    unhexlify(data), order)


def num2hex(num, width=1):
    """
    整数转为指定长度的十六进制字符串，不足补0
    >>> num2hex(1000, width=4)
    '03e8'
    :param num: 整数
    :param width: 16进制字符串长度， 默认为1
    :return str
    """
    return '{:0>{width}}'.format(hex(num)[2:].replace('L', ''),
                                 width=width)
def _byte_unpack(num, byte_n=4):
    # 分解后元组长度
    _len = 4
    # 步长
    step = (byte_n // _len) * 2
    hex_str = num2hex(num=num, width=byte_n * 2)
    split_v = list(range(len(hex_str)))[::step] + [len(hex_str)]
    return tuple(int(hex_str[s:e], base=16) for s, e in zip(split_v[:-1], split_v[1:]))


def _byte_pack(byte_array, byte_n=4):
    _len = 4
    # byte_array每一项16进制字符串的长度
    width = (byte_n // _len) * 2
    if len(byte_array) != _len:
        raise ValueError('byte_array length must be 4.')
    return int(''.join([num2hex(num=v, width=width)
                        for v in byte_array]), 16)

def loop_left_shift(num, offset, base=32):
    """
    循环向左移位
    >>> loop_left_shift(0b11010000, 3, base=8)
    >>> 0b10000110
    """
    bin_str = '{:0>{width}}'.format(bin(num)[2:], width=base)
    rem = offset % base
    return int(bin_str[rem:] + bin_str[:rem], 2)