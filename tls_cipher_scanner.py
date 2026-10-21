import os
import sys
import ssl
import socket
import argparse
import json
from urllib.parse import urlparse

DEPRECATED_PROTOCOLS = {
    "SSLv2": "SSLv2 (Deprecated)",
    "SSLv3": "SSLv3 (Deprecated)",
    ssl.TLSVersion.SSLv3: "SSLv3 (Deprecated)",
    ssl.TLSVersion.TLSv1: "TLSv1.0 (Deprecated)",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1 (Deprecated)",
}

SECURE_PROTOCOLS = {
    ssl.TLSVersion.TLSv1_2: "TLSv1.2 (Secure)",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3 (Secure)",
}

TLS_1_3_CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_256_GCM_SHA256",
}

INSECURE_CIPHER_TERMS = ["RC4", "DES", "RC2", "MD5", "NULL", "EXPORT", "anon", "IDEA", "SEED"]

def has_forward_secrecy(cipher_name):
    """Determine whether a cipher suite provides Perfect Forward Secrecy (PFS)."""
    if not cipher_name or not isinstance(cipher_name, str):
        return False
    upper = cipher_name.upper()
    if is_tls13_cipher(upper):
        return True
    return "ECDHE" in upper or "DHE" in upper or "EDH" in upper

def is_tls13_cipher(cipher_name):
    if not cipher_name or not isinstance(cipher_name, str):
        return False
    upper = cipher_name.upper()
    if upper in TLS_1_3_CIPHER_SUITES:
        return True
    if upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20_"):
        return True
    return False

def is_tls13_cipher_suite(cipher_name):
    return is_tls13_cipher(cipher_name)

def check_tls13_cipher_suite(cipher_name):
    is_tls13 = is_tls13_cipher(cipher_name)
    issues = check_cipher_security(cipher_name)
    return {
        "cipher": cipher_name,
        "is_tls13": is_tls13,
        "secure": is_tls13 and len(issues) == 0,
        "issues": issues,
    }

def check_cipher_security(cipher_name):
    upper_name = cipher_name.upper()
    issues = []
    if "CBC3" in upper_name or "3DES" in upper_name:
        issues.append("Weak/Deprecated cipher term: 3DES")
    for term in INSECURE_CIPHER_TERMS:
        if term in upper_name:
            issues.append(f"Weak/Deprecated cipher term: {term}")
    if "CBC" in upper_name and "AEAD" not in upper_name:
        issues.append("CBC mode cipher (potential padding oracle): CBC")
    return issues

def format_json(results, indent=2, sort_keys=False):
    return json.dumps(results, indent=indent, sort_keys=sort_keys, default=str)

def format_json_output(results, indent=2, sort_keys=False):
    return format_json(results, indent=indent, sort_keys=sort_keys)

def format_text_output(results):
    lines = [
        "",
        "--- Scan Results ---",
        f"Target: {results['host']}:{results['port']}",
        "",
        "Supported Protocols:",
    ]
    for proto, supported in results.get("supported_protocols", {}).items():
        status = "SUPPORTED" if supported else "Not supported"
        lines.append(f"  - {proto}: {status}")

    lines.append("")
    lines.append("Active Cipher:")
    if results.get("ciphers"):
        for c in results["ciphers"]:
            lines.append(f"  - Name: {c['name']} ({c['version']}, {c['bits']} bits)")
    else:
        lines.append("  - None retrieved")

    lines.append("")
    lines.append("Vulnerabilities / Flags:")
    if results.get("vulnerabilities"):
        for v in results["vulnerabilities"]:
            lines.append(f"  [!] {v}")
    else:
        lines.append("  [+] No deprecated protocols or weak ciphers flagged.")
    return "\n".join(lines)

def scan_endpoint(host, port=443, timeout=5.0):
    results = {
        "host": host,
        "port": port,
        "supported_protocols": {},
        "deprecated_protocols_found": [],
        "ciphers": [],
        "vulnerabilities": [],
        "tls13_supported": False,
    }

    protocols_to_test = [
        ("SSLv2", "SSLv2"),
        ("SSLv3", "SSLv3"),
        (ssl.TLSVersion.TLSv1, "TLSv1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
        (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
        (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
    ]

    for proto_version, proto_name in protocols_to_test:
        try:
            context = ssl.create_default_context()
            if isinstance(proto_version, ssl.TLSVersion):
                context.minimum_version = proto_version
                context.maximum_version = proto_version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    results["supported_protocols"][proto_name] = True
                    if proto_name in ["SSLv2", "SSLv3"] or proto_version in DEPRECATED_PROTOCOLS:
                        if proto_name not in results["deprecated_protocols_found"]:
                            results["deprecated_protocols_found"].append(proto_name)
                        v_msg = f"Supports deprecated protocol: {proto_name}"
                        if v_msg not in results["vulnerabilities"]:
                            results["vulnerabilities"].append(v_msg)
        except Exception:
            results["supported_protocols"][proto_name] = False

    results["tls13_supported"] = results["supported_protocols"].get("TLSv1.3", False)

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    results["ciphers"].append({
                        "name": cipher_name,
                        "version": cipher[1],
                        "bits": cipher[2],
                        "is_tls13": is_tls13_cipher(cipher_name) or cipher[1] == "TLSv1.3",
                    })
                    issues = check_cipher_security(cipher_name)
                    for issue in issues:
                        results["vulnerabilities"].append(f"Cipher {cipher_name}: {issue}")
    except Exception as e:
        results["vulnerabilities"].append(f"Failed to retrieve active cipher: {str(e)}")

    return results

def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit SSL/TLS cipher suites and protocol versions.")
    parser.add_argument("target", help="Domain name or URL to scan")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port to scan (default: 443)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args(argv)

    target = args.target
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or args.port
    else:
        host = target
        port = args.port

    if not host:
        print(f"Error: Invalid target {target}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print(f"Scanning {host}:{port} for TLS protocols and ciphers...")
    results = scan_endpoint(host, port)

    if args.json:
        print(format_json(results))
    else:
        print(format_text_output(results))

if __name__ == "__main__":
    main()
