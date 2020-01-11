import base64
import importlib

ctr = importlib.import_module("3_block_and_stream.18_ctr_stream_cipher")
aes = importlib.import_module("2_block_crypto.11_detection_oracle")

aes_key = aes.generate_random_bytes(16)
encoded_strings = list(map(base64.b64decode, ["SSBoYXZlIG2ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
                                              "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
                                              "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
                                              "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
                                              "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
                                              "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                                              "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
                                              "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                                              "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
                                              "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
                                              "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
                                              "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
                                              "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
                                              "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
                                              "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
                                              "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
                                              "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
                                              "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
                                              "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
                                              "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
                                              "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
                                              "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
                                              "U2hlIHJvZGUgdG8gaGFycmllcnM/",
                                              "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
                                              "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
                                              "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
                                              "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
                                              "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
                                              "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
                                              "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
                                              "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
                                              "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
                                              "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
                                              "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
                                              "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
                                              "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
                                              "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
                                              "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
                                              "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
                                              "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]))
encrypted_strings = list(map(ctr.ctr_mode, encoded_strings,
                             [aes_key] * len(encoded_strings),
                             [b'\x00' * 8] * len(encoded_strings)))


def guess_encrypted_string():
    separated_encrypted_strings = list(map(lambda x: list(x), encrypted_strings))


def main():
    guess_encrypted_string()


if __name__ == '__main__':
    main()
