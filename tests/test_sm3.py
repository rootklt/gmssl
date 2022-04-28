from gmssl import sm3

if __name__ == '__main__':
    y = sm3.sm3_hash(b'hello')
    print(y)
