import importlib
import random
import time

import web

urls = ('/', 'index',
        '/test', 'test')
app = web.application(urls, globals())

sha1 = importlib.import_module("4_stream_and_randomness.28_sha1_mac")
key = bytes(random.sample(range(256), 16))


class test:
    def GET(self):
        data = web.input()
        file_name = data.file.encode()
        signature = data.signature.encode()
        insecure_compare(file_name, signature)


class index:
    def GET(self):
        return "Hello, world!"


def insecure_compare(file_name, signature):
    file_name_hmac = sha1.sha1(key + file_name)
    for i in range(len(file_name_hmac)):
        time.sleep(0.05)
        if file_name_hmac[i] != signature[i]:
            app.internalerror()
            return "Failure"
    time.sleep(.50)
    web.webapi.ok()
    return "Success"


if __name__ == '__main__':
    app.run()
