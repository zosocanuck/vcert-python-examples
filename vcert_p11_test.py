import base64
import subprocess
import datetime
import time

from asn1crypto import pem
from asn1crypto.x509 import Certificate, TbsCertificate, Time, Name
from asn1crypto.keys import RSAPublicKey
from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from os import environ

import pkcs11
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.dsa import decode_dsa_signature
from pkcs11.util.ec import decode_ecdsa_signature
from pkcs11.util.x509 import decode_x509_certificate, decode_x509_public_key
from pkcs11 import (
    Attribute,
    KeyType,
    Mechanism,
)

from vcert import (CertificateRequest, Connection, CloudConnection,
                   FakeConnection, TPPConnection, RevocationRequest)

# Initialise our PKCS#11 library
lib = pkcs11.lib('/usr/local/lib/softhsm/libsofthsm2.so')
token = lib.get_token(token_label='My token 1')
cn = 'vcert1001.venafi.example'
with token.open(user_pin='1234') as session:
        pub, priv = session.generate_keypair(KeyType.RSA, 2048)

        info = CertificationRequestInfo({
            'version': 0,
            'subject': Name.build({
                'common_name': cn,
            }),
            'subject_pk_info': {
                'algorithm': {
                    'algorithm': 'rsa',
                    'parameters': None,
                },
                'public_key': RSAPublicKey.load(encode_rsa_public_key(pub)),
            },
        })

        # Sign the CSR Info
        value = priv.sign(info.dump(),
                          mechanism=Mechanism.SHA1_RSA_PKCS)

        csr = CertificationRequest({
            'certification_request_info': info,
            'signature_algorithm': {
                'algorithm': 'sha1_rsa',
                'parameters': None,
            },
            'signature': value,
        })
        certpem = pem.armor('CERTIFICATE REQUEST', csr.dump()).decode()
        # Pipe our CSR to OpenSSL to verify it
        with subprocess.Popen(('/bin/openssl', 'req',
                               '-inform', 'der',
                               '-noout',
                               '-verify'),
                              stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL) as proc:

            proc.stdin.write(csr.dump())
            proc.stdin.close()

        user = environ.get('TPPUSER')
        password = environ.get('TPPPASSWORD')
        url = environ.get('TPPURL')
        zone = environ.get("ZONE")
        conn = Connection(url=url, user=user, password=password, http_request_kwargs={"verify": False})
        request = CertificateRequest(common_name=cn)
        request.csr = certpem
        conn.request_cert(request, zone)
        # and wait for signing
        while True:
           cert = conn.retrieve_cert(request)
           if cert:
              break
           else:
              time.sleep(5)

        # after that print cert and key
        print(cert.full_chain, sep="\n")
