import pytest
from tls_cipher_scanner import check_cipher_security

def test_tls13_cipher_suites_classification():
    # check_cipher_security returns a list of issues (empty list means secure/no issues)
    assert check_cipher_security("TLS_AES_128_GCM_SHA256") == []
    assert check_cipher_security("TLS_CHACHA20_POLY1305_SHA256") == []
    assert check_cipher_security("TLS_AES_256_GCM_SHA256") == []
