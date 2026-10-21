import pytest
from unittest.mock import patch, MagicMock
from tls_cipher_scanner import (
    check_cipher_security,
    is_tls13_cipher,
    is_tls13_cipher_suite,
    check_tls13_cipher_suite,
    scan_endpoint,
    TLS_1_3_CIPHER_SUITES,
)

def test_tls13_cipher_suites_classification():
    assert check_cipher_security("TLS_AES_128_GCM_SHA256") == []
    assert check_cipher_security("TLS_CHACHA20_POLY1305_SHA256") == []
    assert check_cipher_security("TLS_AES_256_GCM_SHA256") == []
    assert check_cipher_security("TLS_AES_256_GCM_SHA384") == []
    assert check_cipher_security("TLS_AES_128_CCM_SHA256") == []
    assert check_cipher_security("TLS_AES_128_CCM_8_SHA256") == []

def test_is_tls13_cipher():
    for suite in TLS_1_3_CIPHER_SUITES:
        assert is_tls13_cipher(suite) is True
        assert is_tls13_cipher(suite.lower()) is True
        assert is_tls13_cipher_suite(suite) is True

    assert is_tls13_cipher("ECDHE-RSA-AES128-GCM-SHA256") is False
    assert is_tls13_cipher("RC4-SHA") is False
    assert is_tls13_cipher("DES-CBC3-SHA") is False
    assert is_tls13_cipher("") is False
    assert is_tls13_cipher(None) is False
    assert is_tls13_cipher_suite("RC4-SHA") is False

def test_check_tls13_cipher_suite():
    res_secure = check_tls13_cipher_suite("TLS_AES_128_GCM_SHA256")
    assert res_secure["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert res_secure["is_tls13"] is True
    assert res_secure["secure"] is True
    assert res_secure["issues"] == []

    res_insecure = check_tls13_cipher_suite("RC4-SHA")
    assert res_insecure["cipher"] == "RC4-SHA"
    assert res_insecure["is_tls13"] is False
    assert res_insecure["secure"] is False
    assert len(res_insecure["issues"]) > 0

@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_scan_endpoint_tls13(mock_create_context, mock_create_connection):
    mock_sock = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_sock

    mock_context = MagicMock()
    mock_create_context.return_value = mock_context
    mock_ssock = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    results = scan_endpoint("example.com", 443)
    assert results["tls13_supported"] is True
    assert len(results["ciphers"]) == 1
    assert results["ciphers"][0]["name"] == "TLS_AES_256_GCM_SHA384"
    assert results["ciphers"][0]["version"] == "TLSv1.3"
    assert results["ciphers"][0]["is_tls13"] is True
