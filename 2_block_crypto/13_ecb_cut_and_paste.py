import importlib

oracle = importlib.import_module('11_detection_oracle')
pad = importlib.import_module('9_pkcs7')

aes_key = oracle.generate_random_bytes(16)


def cookie_parsing_routine(cookie_string):
    return dict(map(lambda s: s.split('='), cookie_string.split("&")))


def encode_cookie(parsed_dict):
    return "&".join("=".join(_) for _ in parsed_dict.items())


def profile_for(email_string):
    global aes_key
    assert "&" not in email_string
    assert "=" not in email_string
    assert "@" in email_string
    user_dict = {"email": email_string, "uid": "10", "role": "user"}
    cookie = pad.pkcs(encode_cookie(user_dict), 16)
    return oracle.cbc.ecb_encode_with_key(cookie, aes_key)


def decode_and_parse(encoded_cookie):
    global aes_key
    decoded_cookie = oracle.cbc.ecb_decode_with_key(encoded_cookie, aes_key).decode().strip("\x04")
    return cookie_parsing_routine(decoded_cookie)


def make_admin_profile():
    crafted_email = b'AAAAAAAAAA' + b'admin' + b'\x04' * 11 + b'\x40foo.com'
    crafted_cookie = profile_for(crafted_email.decode())
    paste_end = crafted_cookie[16:32]
    admin_email = b'A' * 20 + b'\x40fooo.com'
    admin_cookie = profile_for(admin_email.decode())
    admin_cookie = admin_cookie[:-16] + paste_end
    return decode_and_parse(admin_cookie)


def main():
    print(make_admin_profile())


if __name__ == '__main__':
    main()
