import pytest
from unittest.mock import patch, MagicMock
from tls_cipher_scanner import scan_endpoint

@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_sslv2_and_sslv3_detection_and_warning(mock_create_context, mock_create_connection):
    mock_sock = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_sock

    mock_context = MagicMock()
    mock_create_context.return_value = mock_context
    mock_ssock = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)

    results = scan_endpoint("example.com", 443)

    assert results["supported_protocols"].get("SSLv2") is True
    assert results["supported_protocols"].get("SSLv3") is True
    assert "SSLv2" in results["deprecated_protocols_found"]
    assert "SSLv3" in results["deprecated_protocols_found"]
    assert any("SSLv2" in v for v in results["vulnerabilities"])
    assert any("SSLv3" in v for v in results["vulnerabilities"])
