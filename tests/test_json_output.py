import json
import pytest
from unittest.mock import patch
from tls_cipher_scanner import format_json, format_json_output, format_text_output, main

@pytest.fixture
def sample_results():
    return {
        "host": "example.com",
        "port": 443,
        "supported_protocols": {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1.0": False,
            "TLSv1.1": False,
            "TLSv1.2": True,
            "TLSv1.3": True,
        },
        "deprecated_protocols_found": [],
        "ciphers": [
            {
                "name": "TLS_AES_256_GCM_SHA384",
                "version": "TLSv1.3",
                "bits": 256,
                "is_tls13": True,
            }
        ],
        "vulnerabilities": [],
        "tls13_supported": True,
    }

def test_format_json_valid(sample_results):
    json_str = format_json(sample_results)
    parsed = json.loads(json_str)
    assert parsed["host"] == "example.com"
    assert parsed["port"] == 443
    assert parsed["tls13_supported"] is True
    assert len(parsed["ciphers"]) == 1
    assert parsed["ciphers"][0]["is_tls13"] is True
    assert '  "host": "example.com"' in json_str

def test_format_json_output_alias(sample_results):
    assert format_json_output(sample_results) == format_json(sample_results)

def test_format_json_custom_indent(sample_results):
    json_str = format_json(sample_results, indent=4)
    assert '    "host": "example.com"' in json_str

def test_format_text_output(sample_results):
    text = format_text_output(sample_results)
    assert "Target: example.com:443" in text
    assert "TLSv1.3: SUPPORTED" in text
    assert "TLS_AES_256_GCM_SHA384" in text
    assert "No deprecated protocols or weak ciphers flagged" in text

@patch("tls_cipher_scanner.scan_endpoint")
def test_cli_json_output(mock_scan, sample_results, capsys):
    mock_scan.return_value = sample_results
    main(["example.com", "--json"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["host"] == "example.com"
    assert parsed["tls13_supported"] is True

@patch("tls_cipher_scanner.scan_endpoint")
def test_cli_text_output(mock_scan, sample_results, capsys):
    mock_scan.return_value = sample_results
    main(["example.com"])
    captured = capsys.readouterr()
    assert "Scanning example.com:443" in captured.out
    assert "--- Scan Results ---" in captured.out
