#!/usr/bin/env python3
# coding:utf-8


from random import SystemRandom
from binascii import unhexlify, hexlify

from . import sm3, utils

# 选择素域，设置椭圆曲线参数
ECC_TABLE = {
    'n': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
    'p': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    'g': 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0,
    'a': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    'b': 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
}


class GenSM2KEY(object):
    '''
        sm2 key generator
    '''

    def __init__(self, ecc_table):
        self.curve = {
            'A': ecc_table['a'],
            'B': ecc_table['b'],
            'P': ecc_table['p'],
            'N': ecc_table['n'],
            'Gx': ecc_table['g'] >> 256,
            'Gy': ecc_table['g'] & ((0x1 << 256) - 1)
        }
        self.compressed = False

    def set_compressed(self, compressed: bool = False):
        self.compressed = compressed

    def privateKey(self, secret=None) -> bytes:
        self.secret = secret or SystemRandom().randrange(1, self.curve['N'])
        return f"{self.secret:064x}".encode()

    def publicKey(self) -> bytes:
        '''
        计算公钥
        '''
        curve = self.curve
        xPublicKey, yPublicKey = utils.multiply(
            (curve['Gx'], curve['Gy']), self.secret, A=curve['A'], P=curve['P'], N=curve['N'])
        # type: ignore
        return {True: f'\x04{xPublicKey:x}'.encode(), False: f"\x04{xPublicKey:064x}{yPublicKey:064x}".encode()}.get(self.compressed)

    def gen_key_pair(self, secret=None) -> tuple:
        '''
        生成(d,n)的密钥对
        '''
        return self.privateKey(secret), self.publicKey()


class CryptSM2(GenSM2KEY):
    def __init__(self, ecc_table=ECC_TABLE, mode=1):
        """
        mode: 0-C1C2C3, 1-C1C3C2 (default is 1)
        """
        super().__init__(ecc_table)
        self.mode = mode
        self.ecc_table = ecc_table
        self._init()

    def _init(self):
        self.para_len = len(f"{self.ecc_table['n']:x}")
        self.ecc_a3 = (self.ecc_table['a'] + 3) % self.ecc_table['p']
        assert self.mode in (0, 1), 'mode must be one of (0, 1)'

    def _check_key(self, key: bytes) -> bytes:
        if key.startswith(b'04') and len(key) == 66 or len(key) == 130:
            return key[2:]
        return key

    def set_private_key(self, private_key: bytes):
        self.private_key = self._check_key(private_key)

    def set_public_key(self, public_key: bytes):
        self.public_key = self._check_key(public_key)

    def set_key_pair(self, private_key: bytes, public_key: bytes):
        self.private_key = self._check_key(private_key)
        self.public_key = self._check_key(public_key)

    def _kg(self, k: int, Point: bytes) -> bytes:
        '''
        kP运算
        '''
        Point = f'{Point.decode()}1'.encode()
        mask_str = '8' + '0'*(self.para_len - 1)
        mask = int(mask_str, 16)

        Temp = Point
        flag = False
        for _ in range(self.para_len * 4):
            if (flag):
                Temp = self._double_point(Temp)  # type: ignore
            if (k & mask) != 0:
                if (flag):
                    Temp = self._add_point(Temp, Point)
                else:
                    flag = True
                    Temp = Point
            k = k << 1
        return self._convert_jacb_to_nor(Temp)  # type: ignore

    def _double_point(self, Point: bytes):
        '''
        倍点
        '''
        l = len(Point)
        len_2 = 2 * self.para_len
        if l < len_2:
            return  # type: ignore

        x1 = int(Point[:self.para_len], 16)
        y1 = int(Point[self.para_len:len_2], 16)
        z1 = 1 if l == len_2 else int(Point[len_2:], 16)

        T6 = (z1**2) % self.ecc_table['p']
        T2 = (y1**2) % self.ecc_table['p']
        T3 = (x1 + T6) % self.ecc_table['p']
        T4 = (x1 - T6) % self.ecc_table['p']
        T1 = (T3 * T4) % self.ecc_table['p']
        T3 = (y1 * z1) % self.ecc_table['p']
        T4 = (T2 * 8) % self.ecc_table['p']
        T5 = (x1 * T4) % self.ecc_table['p']
        T1 = (T1 * 3) % self.ecc_table['p']
        T6 = (T6 * T6) % self.ecc_table['p']
        T6 = (self.ecc_a3 * T6) % self.ecc_table['p']
        T1 = (T1 + T6) % self.ecc_table['p']
        z3 = (T3 + T3) % self.ecc_table['p']
        T3 = (T1 * T1) % self.ecc_table['p']
        T2 = (T2 * T4) % self.ecc_table['p']
        x3 = (T3 - T5) % self.ecc_table['p']

        if (T5 % 2) == 1:
            T4 = (
                T5 + ((T5 + self.ecc_table['p']) >> 1) - T3) % self.ecc_table['p']
        else:
            T4 = (T5 + (T5 >> 1) - T3) % self.ecc_table['p']

        T1 = (T1 * T4) % self.ecc_table['p']
        y3 = (T1 - T2) % self.ecc_table['p']

        form = f'{{:0{self.para_len}x}}'*3

        return form.format(x3, y3, z3).encode()

    def _add_point(self, P1: bytes, P2: bytes):
        '''
        点加函数,P2点为仿射坐标即z=1,P1为Jacobian加重射影坐标
        '''
        len_2 = 2 * self.para_len
        l1 = len(P1)
        l2 = len(P2)

        if (l1 < len_2) or (l2 < len_2):
            return  # type: ignore

        X1 = int(P1[:self.para_len], 16)
        Y1 = int(P1[self.para_len:len_2], 16)
        Z1 = 1 if (l1 == len_2) else int(P1[len_2:], 16)

        x2 = int(P2[:self.para_len], 16)
        y2 = int(P2[self.para_len:len_2], 16)

        T1 = (Z1**2) % self.ecc_table['p']
        T2 = (y2 * Z1) % self.ecc_table['p']
        T3 = (x2 * T1) % self.ecc_table['p']
        T1 = (T1 * T2) % self.ecc_table['p']
        T2 = (T3 - X1) % self.ecc_table['p']
        T3 = (T3 + X1) % self.ecc_table['p']
        T4 = (T2 * T2) % self.ecc_table['p']
        T1 = (T1 - Y1) % self.ecc_table['p']
        Z3 = (Z1 * T2) % self.ecc_table['p']
        T2 = (T2 * T4) % self.ecc_table['p']
        T3 = (T3 * T4) % self.ecc_table['p']
        T5 = (T1 * T1) % self.ecc_table['p']
        T4 = (X1 * T4) % self.ecc_table['p']
        X3 = (T5 - T3) % self.ecc_table['p']
        T2 = (Y1 * T2) % self.ecc_table['p']
        T3 = (T4 - X3) % self.ecc_table['p']
        T1 = (T1 * T3) % self.ecc_table['p']
        Y3 = (T1 - T2) % self.ecc_table['p']

        form = f'{{:0{self.para_len}x}}'*3
        return form.format(X3, Y3, Z3).encode()

    def _convert_jacb_to_nor(self, Point: bytes):
        '''
        Jacobian加重射影坐标转换成仿射坐标
        '''
        len_2 = 2 * self.para_len

        x = int(Point[:self.para_len], 16)
        y = int(Point[self.para_len:len_2], 16)
        z = int(Point[len_2:], 16)

        z_inv = pow(z, self.ecc_table['p'] - 2, self.ecc_table['p'])

        z_invSquar = (z_inv ** 2) % self.ecc_table['p']
        z_invQube = (z_inv**3) % self.ecc_table['p']

        x_new = (x * z_invSquar) % self.ecc_table['p']
        y_new = (y * z_invQube) % self.ecc_table['p']
        z_new = (z * z_inv) % self.ecc_table['p']

        if z_new != 1:
            return  # type: ignore
        form = f'{{:0{self.para_len}x}}'*2
        return form.format(x_new, y_new).encode()

    def verify(self, Sign: bytes, data: bytes) -> bool:
        '''
        验签函数，sign签名r||s，E消息hash，public_key公钥
        '''

        r = int(Sign[:self.para_len], 16)
        s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % self.ecc_table['n']
        if t == 0:
            return False
        G = self.ecc_table['g']
        P1 = self._kg(s, f"{G:x}".encode())
        P2 = self._kg(t, self.public_key)
        # print(P1)
        # print(P2)
        if P1 == P2:
            P1 = f'{P1.decode()}1'.encode()
            P1 = self._double_point(P1)
        else:
            P1 = f'{P1.decode()}1'.encode()
            P1 = self._add_point(P1, P2)
            P1 = self._convert_jacb_to_nor(P1)

        x = int(P1[:self.para_len], 16)  # type: ignore
        return r == (e + x) % self.ecc_table['n']

    def sign(self, data: bytes, K: bytes) -> bytes:
        '''
        签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        '''
        e = int(data.hex(), 16)
        d = int(self.private_key, 16)
        k = int(K, 16)
        G = self.ecc_table['g']

        P1 = self._kg(k, f"{G:x}".encode())

        x = int(P1[:self.para_len], 16)
        R = (e + x) % self.ecc_table['n']
        if R == 0 or R + k == self.ecc_table['n']:
            return  # type: ignore
        d_1 = pow(d+1, self.ecc_table['n'] - 2, self.ecc_table['n'])
        S = (d_1*(k + R) - R) % self.ecc_table['n']
        if S == 0:
            return  # type: ignore

        return f'{R:064x}{S:064x}'.encode()

    def encrypt(self, plaintext: bytes) -> bytes:
        '''
        加密函数，data消息(bytes)
        :params plaintext bytes 明文
        :returns bytes 返回加密后的raw
        '''

        msg = plaintext.hex()  # type: ignore # 将明文转成16进制，并计算长度
        ml = len(msg)
        k = utils.random_hex(self.para_len)  # 获取随机的16进制字符串
        G = self.ecc_table['g']
        C1 = self._kg(int(k, 16), f"{G:x}".encode()).decode()

        xy = self._kg(int(k, 16), self.public_key)  # 将随机字符与公钥计算kg值

        x2 = xy[:self.para_len].decode()
        y2 = xy[self.para_len:2*self.para_len].decode()

        t = sm3.sm3_kdf(xy, ml//2)

        if int(t, 16) == 0:
            return  # type: ignore
        form = f'{{:0{ml}x}}'
        C2 = form.format(int(msg, 16) ^ int(t, 16))
        C3 = sm3.sm3_hash(unhexlify(f'{x2}{msg}{y2}')).decode()

        return unhexlify(f'04{C1:s}{C3:s}{C2:s}') if self.mode else unhexlify(f'04{C1:s}{C2:s}{C3:s}')

    def decrypt(self, cipher: bytes) -> bytes:
        '''
        解密函数，data密文(bytes)
        :params cipher bytes 密文
        :returns bytes 原始明文
        '''
        if cipher.startswith(b'\x04'):
            cipher = cipher[1:]
        cipher = cipher.hex().encode()
        len_2 = 2 * self.para_len
        len_3 = len_2 + 64

        #mode = 0
        C1 = cipher[:len_2]
        C2 = cipher[len_2:-64]
        C3 = cipher[-64:]

        if self.mode:  # mode = 1
            C2 = cipher[len_3:]
            C3 = cipher[len_2:len_3]

        xy = self._kg(int(self.private_key, 16), C1)
        # print('xy = %s' % xy)
        x2 = xy[:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)

        t = sm3.sm3_kdf(xy, cl//2)
        if int(t, 16) == 0:
            return None  # type: ignore
        form = f'{{:0{cl}x}}'
        M = form.format(int(C2, 16) ^ int(t, 16))
        u = sm3.sm3_hash(unhexlify(f'{x2.decode():s}{M:s}{y2.decode():s}'))
        assert C3 == u, '数据完整性受破坏。'
        return unhexlify(M)

    def _sm3_z(self, data: bytes):
        """
        SM3WITHSM2 签名规则:  SM2.sign(SM3(Z+MSG)，PrivateKey)
        其中: z = Hash256(Len(ID) + ID + a + b + xG + yG + xA + yA)
        """
        A = self.ecc_table['a']
        B = self.ecc_table['b']
        G = self.ecc_table['g']
        # sm3withsm2 的 z 值
        z = unhexlify(b'0080'+b'31323334353637383132333435363738' +
                      f"{A:x}{B:x}{G:x}".encode() + self.public_key)

        Za = sm3.sm3_hash(z).decode()
        M_ = (Za + data.hex()).encode('utf-8')
        return sm3.sm3_hash(M_)

    def sign_with_sm3(self, data: bytes, random_hex_str=None):
        sign_data = hexlify(self._sm3_z(data))
        if random_hex_str is None:
            random_hex_str = utils.random_hex(self.para_len)
        return self.sign(sign_data, random_hex_str)

    def verify_with_sm3(self, sign, data):
        sign_data = hexlify(self._sm3_z(data))
        return self.verify(sign, sign_data)
