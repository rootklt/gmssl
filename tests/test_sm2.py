import base64
import binascii
from gmssl import sm2, utils


def test_sm2():
    private_key = b'00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = b'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    # private_key = b'54232d8aaa3209ee123e07c34314e50e29fbb941496f92e219eb62c5bd40d968'
    # public_key = b'044a77c33fa976ddab1d8e2ad05694f01151ed39892832947fbcb4a89199db72bc5db91b29616009f0b504459ad72f97b078cf35aebd32b6066003dd81db9a3244'
    # c = b'04193e23bd85dcaae13f0a7d2abf90459710942f98f9813536019d282ed5466c81efed9573da77bf69c1c3c9e3eaff0316abe3581fab08f1897b969fe1d0dd520e7797ffaa2005daa993d9b94171137970e25bf7b5c84b7e39d3a2fd95cecdac780ea3c706a64315e6b06e8f'
    sm2_crypt = sm2.CryptSM2()
    sm2_crypt.set_key_pair(private_key,public_key)
    data = b"hello world"
    enc_data = sm2_crypt.encrypt(data)
    print(enc_data.hex())


    dec_data = sm2_crypt.decrypt(enc_data)
    print(b"dec_data:%s" % dec_data)
    assert data == dec_data

    print("-----------------test sign and verify---------------")
    random_hex_str = utils.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print(f'sign:{sign}')
    verify = sm2_crypt.verify(sign, data)
    print(f'verify:{verify}')
    assert verify


def test_sm3():
    private_key = b"003945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    public_key = b"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
    random_hex_str = b"59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"

    sm2_crypt = sm2.CryptSM2()
    sm2_crypt.set_key_pair(public_key=public_key, private_key=private_key)
    data = b"message digest"

    print("-----------------test SM2withSM3 sign and verify---------------")
    sign = sm2_crypt.sign_with_sm3(data, random_hex_str)
    print(f'sign: {sign}')
    verify = sm2_crypt.verify_with_sm3(sign, data)
    print(f'verify: {verify}')
    assert verify

test_sm3()
test_sm2()
