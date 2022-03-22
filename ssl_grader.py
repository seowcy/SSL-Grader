# https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art012
# https://gist.github.com/zakird/a8582ced2f50cfe1c702
# https://badssl.com/
# https://moz.com/top500
# pip install sslscan

import re
import sys
import ssl
import math
import json
import socket
import OpenSSL  # https://www.pyopenssl.org/en/stable/index.html, pip install pyopenssl
import certifi
import requests
import subprocess
from ocspchecker import ocspchecker # pip install ocsp-checker
from datetime import datetime, timedelta

BANNER = r"""
  ______    ______   _____        ______  _______          _       ______   ________  _______     
.' ____ \ .' ____ \ |_   _|     .' ___  ||_   __ \        / \     |_   _ `.|_   __  ||_   __ \    
| (___ \_|| (___ \_|  | |      / .'   \_|  | |__) |      / _ \      | | `. \ | |_ \_|  | |__) |   
 _.____`.  _.____`.   | |   _  | |   ____  |  __ /      / ___ \     | |  | | |  _| _   |  __ /    
| \____) || \____) | _| |__/ | \ `.___]  |_| |  \ \_  _/ /   \ \_  _| |_.' /_| |__/ | _| |  \ \_  
 \______.' \______.'|________|  `._____.'|____| |___||____| |____||______.'|________||____| |___| 
"""
OUTPUT_TEMPLATE = r"""
Server = %s
Certificate      : %s/100
Protocol Support : %s/100
Key Exchange     : %s/100
Cipher Strength  : %s/100

Overall Grade : %s

Common Name = %s
Subject Alternative Names = %s
Issuer = %s
Serial Number = %s
SHA1 Thumbprint = %s
Key Type (Bit Length) = %s
Signature Algorithm = %s

OCSP Origin = %s
OCSP Status = %s
CRL Status = %s

The certificate expires %s (%s days from today)

Protocol Support = %s

TLS ciphers supported by the server:
%s

"""

PROTOCOLS = [OpenSSL.SSL.TLSv1_2_METHOD, OpenSSL.SSL.TLSv1_1_METHOD, OpenSSL.SSL.TLSv1_METHOD, OpenSSL.SSL.SSLv23_METHOD]
PROTOCOLS_MAPPING = {6: "TLSv1.2", 5: "TLSv1.1", 4: "TLSv1.0", 3: "SSLv2.3", 0: "UNKNOWN"}
PROTOCOLS_RANKING = {"TLSv1.2": 100, "TLSv1.1": 90, "TLSv1.0": 80, "SSLv2.3": 60,"UNKNOWN": 0}
KEY_TYPE = {OpenSSL.crypto.TYPE_RSA:'rsaEncryption', OpenSSL.crypto.TYPE_DSA:'dsaEncryption', 408:'id-ecPublicKey'}
with open("ciphers.json", 'r') as f:
    CIPHERS_RANKING = json.load(f)


def get_cert_info(hostname):
    # https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python
    # https://en.wikipedia.org/wiki/X.509
    # Basic Certificate Fields: https://tools.ietf.org/html/rfc2459
    host_ip = socket.gethostbyname(hostname)
    cert = ssl.get_server_certificate((host_ip, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    cert_info = {
        'subject': {k.decode(): dict(x509.get_subject().get_components())[k].decode() for k in dict(x509.get_subject().get_components())},
        'pubKey': OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, x509.get_pubkey()).decode(),
        'issuer': {k.decode(): dict(x509.get_issuer().get_components())[k].decode() for k in dict(x509.get_issuer().get_components())},
        'serialNumber': hex(x509.get_serial_number())[2:],
        'signatureAlgorithm': x509.get_signature_algorithm().decode(),
        'version': x509.get_version(),
        'notBefore': datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
        'hasExpired': x509.has_expired()
    }
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name().decode(): str(e) for e in extensions}
    cert_info.update(extension_data)
    return (x509, cert_info)


def verify_certificate_chain(hostname):
    # https://stackoverflow.com/questions/19145097/getting-certificate-chain-with-python-3-3-ssl-module
    try:
        for protocol in PROTOCOLS:
            try: 
                context = OpenSSL.SSL.Context(method=protocol)
                context.set_verify(OpenSSL.SSL.VERIFY_PEER)
                context.load_verify_locations(cafile=certifi.where())
                conn = OpenSSL.SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                conn.settimeout(5)
                conn.connect((hostname, 443))
                conn.setblocking(1)
                conn.do_handshake()
                conn.set_tlsext_host_name(hostname.encode())
                return [{"subject": cert.get_subject(),
                         "issuer": cert.get_issuer(),
                         "fingerprint": cert.digest("sha1").decode()} 
                         for cert in conn.get_verified_chain()]
            except Exception:
                continue
    except Exception as e:
        print(e)
        return []
    return []
    
def convert_datetime(datetime_obj):
    return datetime_obj.strftime("%B %d, %Y")

def protocol_checker(hostname):
    flag = False
    for protocol in PROTOCOLS:
        try:
            context = OpenSSL.SSL.Context(method=protocol)
            context.load_verify_locations(cafile=certifi.where())
            conn = OpenSSL.SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.settimeout(5)
            conn.connect((hostname, 443))
            conn.setblocking(1)
            conn.do_handshake()
            conn.set_tlsext_host_name(hostname.encode())
            flag = True
            break
        except OpenSSL.SSL.Error:
            continue
        except socket.gaierror:
            return 0
        except socket.timeout:
            return 0
        except:
            continue
    if flag:
        return PROTOCOLS_MAPPING[protocol]
    else:
        return PROTOCOLS_MAPPING[0]

def ciphers_checker(hostname):
    # pip install sslscan
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    # https://www.thesslstore.com/blog/cipher-suites-algorithms-security-settings/
    # https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
    # https://wiki.mozilla.org/Security/Server_Side_TLS#Cipher_names_correspondence_table
    try:
        output = subprocess.check_output(['pysslscan', 'scan', '--scan=server.ciphers', '--tls', hostname], stderr=subprocess.DEVNULL).decode()
        output = [line.strip().split('\x1b[0m')[-2] for line in output.split('\n') 
                  if (line.strip().startswith("Accepted") or line.strip().startswith("Preferred"))]
        return output
    except Exception as e:
        print("pysslscan error: %s" % str(e))
        return []

def get_ciphers_scores(ciphers):
    scores = {}
    for cipher in ciphers:
        scores[cipher] = CIPHERS_RANKING[cipher] if cipher in CIPHERS_RANKING else 0
    return scores

def get_ocsp_status(hostname):
    return (ocspchecker.get_ocsp_status(hostname)[2].lstrip("OCSP Status: "),
            ocspchecker.get_ocsp_status(hostname)[1].lstrip("OCSP URL: "))

def get_crls(result):
    pattern = r'URI:(\S+)'
    if "crlDistributionPoints" in result["cert_info"]:
        return re.findall(pattern, result["cert_info"]["crlDistributionPoints"])
    else:
        return []

def is_in_crl(serial_number, crl_list):
    for crl_url in crl_list:
        resp = requests.get(crl_url)
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, resp.content)
        if crl.get_revoked():
            rev_serial_numbers = [rev.get_serial().decode() for rev in crl.get_revoked()]
            if serial_number in rev_serial_numbers:
                return True
    return False

def roundup(x):
    return int(math.ceil(x / 10.0)) * 10

def grade_key(key_type_length):
    # https://www.researchgate.net/figure/Security-and-Key-length-Comparison-of-ECC-vs-RSA-DSA-DH_tbl2_309097688
    # https://crypto.stackexchange.com/questions/8687/security-strength-of-rsa-in-relation-with-the-modulus-size
    # https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/fips140-2/fips1402ig.pdf
    # https://crypto.stackexchange.com/questions/61248/aes-and-ecdh-key
    key_type = key_type_length[0]
    key_length = key_type_length[1]
    if key_type in ['rsaEncryption', 'dsaEncryption']:
        bit_strength = (1/math.log(2))*(1.923*pow(key_length*math.log(2),1/3)*pow(math.log(key_length*math.log(2)),2/3)-4.69)
    else:
        bit_strength = key_length/2
    return min(100, roundup(bit_strength/128 * 100))

def grade_cert(x509, result):
    server = result["hostname"]
    common_name = result["cert_info"]["subject"]["CN"]
    subj_alt_names = result["cert_info"]["subjectAltName"]
    issuer = result["cert_info"]["issuer"]["CN"]
    serial_number = result["cert_info"]["serialNumber"].upper()
    verified = False if not result["cert_chain"] else True
    if verified:
        sha1_thumbprint = result["cert_chain"][0]["fingerprint"].replace(':', '')
    else:
        sha1_thumbprint = ""
    key_type_length = (KEY_TYPE[x509.get_pubkey().type()], x509.get_pubkey().bits())
    key_score = grade_key(key_type_length)
    signature_algo = result["cert_info"]["signatureAlgorithm"]
    not_after = result["cert_info"]["notAfter"]
    expired = result["cert_info"]["hasExpired"]
    ocsp_status, ocsp_origin = get_ocsp_status(result["hostname"])
    crl_list = get_crls(result)
    revoked = is_in_crl(serial_number, crl_list)
    protocol_support = (protocol_checker(result["hostname"]), PROTOCOLS_RANKING[protocol_checker(result["hostname"])])
    ciphers_supported = ciphers_checker(result["hostname"])
    ciphers_scores = get_ciphers_scores(ciphers_supported)
    ciphers_score = max([v for k,v in ciphers_scores.items()]) if ciphers_supported else 0
    if not verified or expired or revoked:
        certificate_score = 0
    elif 'sha1' in signature_algo.lower() or 'md5' in signature_algo.lower():
        certificate_score = 50
    else:
        certificate_score = 100
    total_score = certificate_score + protocol_support[1] + key_score + ciphers_score
    if total_score >= 380:
        overall_grade = 'A+'
    elif total_score >= 360:
        overall_grade = 'A'
    elif total_score >= 340:
        overall_grade = 'B'
    elif total_score >= 320:
        overall_grade = 'C'
    elif total_score >= 300:
        overall_grade = 'D'
    else:
        overall_grade = 'E'

    grade_info = {"Server": server, "Common Name": common_name, "Subject Alternate Names": subj_alt_names.replace("DNS:", ''), "Issuer": issuer,
                    "Serial Number": serial_number, "SHA1 Thumbprint": sha1_thumbprint, "Key Type/Length": key_type_length,
                    "Signature Algorithm": signature_algo, "Not After": convert_datetime(not_after), "Expired": expired,
                    "Protocol Support": protocol_support[0], "Ciphers Supported": ciphers_scores, "Verified": verified,
                    "OCSP Status": ocsp_status, "OCSP Origin": ocsp_origin, "Revoked": revoked,
                    "Certificate Score": certificate_score, "Protocol Score": protocol_support[1],"Key Exchange Score": key_score,
                    "Cipher Strength": ciphers_score, "Overall Grade": overall_grade}
    return grade_info

def format_output(grade_info):
    d1 = datetime.strptime(grade_info["Not After"], "%B %d, %Y")
    d2 = datetime.today()
    days = math.ceil((d1 - d2) / timedelta(days=1))
    output = (grade_info["Server"], grade_info["Certificate Score"], grade_info["Protocol Score"], grade_info["Key Exchange Score"],
                grade_info["Cipher Strength"], grade_info["Overall Grade"], grade_info["Common Name"], grade_info["Subject Alternate Names"],
                grade_info["Issuer"], grade_info["Serial Number"], grade_info["SHA1 Thumbprint"], "%s (%s bits)" % grade_info["Key Type/Length"],
                grade_info["Signature Algorithm"], grade_info["OCSP Origin"], grade_info["OCSP Status"], "GOOD" if not grade_info["Revoked"] else "BAD",
                grade_info["Not After"], days, grade_info["Protocol Support"], ", ".join(grade_info["Ciphers Supported"].keys()))
    return OUTPUT_TEMPLATE % output


if __name__ == "__main__":
    print(BANNER)
    args = sys.argv[1:]
    if len(args) < 1:
        print("Usage: %s [hostname1 [hostname2 [...]]]\n" % sys.argv[0])
        sys.exit(1)
    for hostname in args:
        print("Grading certificate for %s...\n" % hostname)
        try:
            x509, cert_info = get_cert_info(hostname)
            cert_chain = verify_certificate_chain(hostname)
            result = {"hostname": hostname, "cert_info": cert_info, "cert_chain": cert_chain}
            grade_info = grade_cert(x509, result)
        except Exception as e:
            print("\tError encountered: %s" % e)
            continue
        print(format_output(grade_info))
        print('='*100)
