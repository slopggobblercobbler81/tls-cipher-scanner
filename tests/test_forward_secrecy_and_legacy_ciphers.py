import pytest
from tls_cipher_scanner import check_cipher_security, has_forward_secrecy


def test_has_forward_secrecy():
    # Ephemeral ECDHE / DHE ciphers provide PFS
    assert has_forward_secrecy("ECDHE-RSA-AES128-GCM-SHA256") is True
    assert has_forward_secrecy("ECDHE-ECDSA-CHACHA20-POLY1305") is True
    assert has_forward_secrecy("DHE-RSA-AES256-GCM-SHA384") is True
    assert has_forward_secrecy("EDH-RSA-DES-CBC3-SHA") is True

    # TLS 1.3 ciphers always provide PFS
    assert has_forward_secrecy("TLS_AES_128_GCM_SHA256") is True
    assert has_forward_secrecy("TLS_AES_256_GCM_SHA384") is True
    assert has_forward_secrecy("TLS_CHACHA20_POLY1305_SHA256") is True

    # Static RSA or DH key exchanges lack PFS
    assert has_forward_secrecy("AES128-GCM-SHA256") is False
    assert has_forward_secrecy("AES256-SHA256") is False
    assert has_forward_secrecy("RC4-SHA") is False
    assert has_forward_secrecy("") is False
    assert has_forward_secrecy(None) is False


def test_deprecated_idea_and_seed_ciphers():
    # IDEA ciphers
    idea_issues = check_cipher_security("IDEA-CBC-SHA")
    assert any("IDEA" in issue for issue in idea_issues)

    # SEED ciphers
    seed_issues = check_cipher_security("SEED-SHA")
    assert any("SEED" in issue for issue in seed_issues)
