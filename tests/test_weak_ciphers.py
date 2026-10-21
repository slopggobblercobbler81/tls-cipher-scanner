import pytest
from tls_cipher_scanner import check_cipher_security

def test_rc4_and_3des_deprecation_warnings():
    # Verify RC4 ciphers trigger deprecation/weakness warning
    rc4_issues = check_cipher_security("RC4-SHA")
    assert any("RC4" in issue for issue in rc4_issues)

    # Verify 3DES ciphers trigger deprecation/weakness warning
    des_issues = check_cipher_security("DES-CBC3-SHA")
    assert any("3DES" in issue for issue in des_issues)
    
    # Additional variations
    assert any("RC4" in issue for issue in check_cipher_security("ECDHE-RSA-RC4-SHA"))
    assert any("3DES" in issue for issue in check_cipher_security("EDH-RSA-DES-CBC3-SHA"))
