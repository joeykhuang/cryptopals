import binascii


def main():
    buf1 = binascii.unhexlify(input())
    buf2 = binascii.unhexlify(input())
    hexbytes = [_buf1 ^ _buf2 for _buf1, _buf2 in zip(buf1, buf2)]
    print(binascii.hexlify(bytes(hexbytes)))


if __name__ == '__main__':
    main()
