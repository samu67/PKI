from typing import Callable
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from secrets import token_urlsafe
import datetime

# Define name attribute of CA
ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
        ])

# # Generate signing key of CA
# CAkey = ec.generate_private_key(ec.SECP384R1())

with open("CAkey.pem", "rb") as f:
    cakey_content = f.read()

CAkey = serialization.load_pem_private_key(cakey_content,b'password')

CACert = x509.CertificateBuilder().subject_name(
    ca_name
).issuer_name(
    ca_name
).public_key(
    CAkey.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year + 1)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True
).sign(
    CAkey, hashes.SHA256()
)

with open(f"out/_CACert.pem", "wb") as f:
    f.write(CACert.public_bytes(encoding=serialization.Encoding.PEM))
    f.close()

