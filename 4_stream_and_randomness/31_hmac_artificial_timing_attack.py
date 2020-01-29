import time
from urllib import request, error


def construct_url_and_get_response(file_name, signature):
    url_base = 'http://0.0.0.0:8080/test?file='
    url_base += file_name + '&signature=' + signature
    beginning_time = time.perf_counter()
    req = request.Request(url_base)
    try:
        request.urlopen(req)
    except error.HTTPError as e:
        end_time = time.perf_counter()
        return [e.code, end_time - beginning_time]


def find_hmac():
    good_hmac = b''
    for i in range(40):
        char_times = {}
        for _ in range(10):
            buffer_hmac = b'a' * 40
            construct_url_and_get_response('foo', buffer_hmac.decode())
        for possible_char in [i for j in (range(97, 123), range(48, 58)) for i in j]:
            possible_hmac = b''
            possible_hmac += good_hmac + bytes([possible_char]) + b'a' * (39 - len(good_hmac))
            code, response_time = construct_url_and_get_response('foo', possible_hmac.decode())
            char_times[bytes([possible_char])] = response_time
        print(char_times)
        print(max(char_times, key=char_times.get), char_times[max(char_times, key=char_times.get)])
        good_hmac += max(char_times, key=char_times.get)
    code, response_time = construct_url_and_get_response('foo', good_hmac.decode())
    if code == 200:
        print("Success")
        return good_hmac


def main():
    print(find_hmac())
    return None


if __name__ == '__main__':
    main()
