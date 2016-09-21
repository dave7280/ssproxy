#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_long, byref,\
    create_string_buffer, c_void_p

import common

__all__ = ['ciphers']

libcrypto = None
loaded = False

buf_size = 2048


def load_openssl():
    global loaded, libcrypto, buf

    libcrypto = common.find_library(('crypto', 'eay32'),
                                  'EVP_get_cipherbyname',
                                  'libcrypto')
    if libcrypto is None:
        raise Exception('libcrypto(OpenSSL) not found')

    libcrypto.EVP_get_cipherbyname.restype = c_void_p
    libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p

    libcrypto.EVP_CipherInit_ex.argtypes = (c_void_p, c_void_p, c_char_p,
                                            c_char_p, c_char_p, c_int)

    libcrypto.EVP_CipherUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                           c_char_p, c_int)

    libcrypto.EVP_CIPHER_CTX_cleanup.argtypes = (c_void_p,)
    libcrypto.EVP_CIPHER_CTX_free.argtypes = (c_void_p,)
    if hasattr(libcrypto, 'OpenSSL_add_all_ciphers'):
        libcrypto.OpenSSL_add_all_ciphers()

    buf = create_string_buffer(buf_size)
    loaded = True


def load_cipher(cipher_name):
    func_name = 'EVP_' + cipher_name.replace('-', '_')
    if bytes != str:
        func_name = str(func_name, 'utf-8')
    cipher = getattr(libcrypto, func_name, None)
    if cipher:
        cipher.restype = c_void_p
        return cipher()
    return None

class OpenSSLCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
		# cipher when op is 1, otherwise decipher
        self._ctx = None
        if not loaded:
            load_openssl()
        cipher_name = common.to_bytes(cipher_name)
        cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
        # 换个方式加载
        if not cipher:
            cipher = load_cipher(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % cipher_name)
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self._ctx = libcrypto.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise Exception('can not create cipher context')
        r = libcrypto.EVP_CipherInit_ex(self._ctx, cipher, None,
                                        key_ptr, iv_ptr, c_int(op))
        if not r:
            self.clean()
            raise Exception('can not initialize cipher context')

    def update(self, data):
        global buf_size, buf
        cipher_out_len = c_long(0)
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        libcrypto.EVP_CipherUpdate(self._ctx, byref(buf),
                                   byref(cipher_out_len), c_char_p(data), l)
        return buf.raw[:cipher_out_len.value]

    def __del__(self):
        self.clean()

    def clean(self):
        if self._ctx:
            libcrypto.EVP_CIPHER_CTX_cleanup(self._ctx)
            libcrypto.EVP_CIPHER_CTX_free(self._ctx)


ciphers = {
    'aes-128-cfb': (16, 16, OpenSSLCrypto),
    'aes-192-cfb': (24, 16, OpenSSLCrypto),
    'aes-256-cfb': (32, 16, OpenSSLCrypto),
    'aes-128-ofb': (16, 16, OpenSSLCrypto),
    'aes-192-ofb': (24, 16, OpenSSLCrypto),
    'aes-256-ofb': (32, 16, OpenSSLCrypto),
    'aes-128-ctr': (16, 16, OpenSSLCrypto),
    'aes-192-ctr': (24, 16, OpenSSLCrypto),
    'aes-256-ctr': (32, 16, OpenSSLCrypto),
    'aes-128-cfb8': (16, 16, OpenSSLCrypto),
    'aes-192-cfb8': (24, 16, OpenSSLCrypto),
    'aes-256-cfb8': (32, 16, OpenSSLCrypto),
    'aes-128-cfb1': (16, 16, OpenSSLCrypto),
    'aes-192-cfb1': (24, 16, OpenSSLCrypto),
    'aes-256-cfb1': (32, 16, OpenSSLCrypto),
    'bf-cfb': (16, 8, OpenSSLCrypto),
    'camellia-128-cfb': (16, 16, OpenSSLCrypto),
    'camellia-192-cfb': (24, 16, OpenSSLCrypto),
    'camellia-256-cfb': (32, 16, OpenSSLCrypto),
    'cast5-cfb': (16, 8, OpenSSLCrypto),
    'des-cfb': (8, 8, OpenSSLCrypto),
    'idea-cfb': (16, 8, OpenSSLCrypto),
    'rc2-cfb': (16, 8, OpenSSLCrypto),
    'rc4': (16, 0, OpenSSLCrypto),
    'seed-cfb': (16, 16, OpenSSLCrypto),
}


def run_method(method):

    cipher = OpenSSLCrypto(method, b'k' * 32, b'i' * 16, 1)
    decipher = OpenSSLCrypto(method, b'k' * 32, b'i' * 16, 0)

    run_cipher(method, cipher, decipher)


def run_cipher(method, cipher, decipher):
    from os import urandom
    import random
    import time

    BLOCK_SIZE = 16384
    rounds = 1 * 1024
    plain = urandom(BLOCK_SIZE * rounds)

    results = []
    pos = 0
    print('%s test start' % method)
    start = time.time()
    while pos < len(plain):
        l = random.randint(100, 32768)
        c = cipher.update(plain[pos:pos + l])
        results.append(c)
        pos += l
    pos = 0
    c = b''.join(results)
    results = []
    while pos < len(plain):
        l = random.randint(100, 32768)
        results.append(decipher.update(c[pos:pos + l]))
        pos += l
    end = time.time()
    print('speed: %d bytes/s' % (BLOCK_SIZE * rounds / (end - start)))
    assert b''.join(results) == plain


def test_aes_128_cfb():
    run_method('aes-128-cfb')


def test_aes_256_cfb():
    run_method('aes-256-cfb')


def test_aes_128_cfb8():
    run_method('aes-128-cfb8')


def test_aes_256_ofb():
    run_method('aes-256-ofb')


def test_aes_256_ctr():
    run_method('aes-256-ctr')


def test_bf_cfb():
    run_method('bf-cfb')


def test_rc4():
    run_method('rc4')


if __name__ == '__main__':
    test_aes_128_cfb()
    test_aes_256_cfb()
    test_aes_128_cfb8()
    test_aes_256_ofb()
    test_aes_256_ctr()
    test_bf_cfb()
    test_rc4()
