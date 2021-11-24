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

# Generate signing key of CA
CAkey = ec.generate_private_key(ec.SECP384R1())
with open("out/CAkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
    f.close()


def gen_key_cert_signed(ca_name, CAkey, Server_name, password=None):

    if password == None:
        password = token_urlsafe(32)
    
    # Generate private and public key of the database
    Key = ec.generate_private_key(ec.SECP384R1())
    PubKey = Key.public_key()
    with open(f"out/{Server_name}-Key.pem", "wb") as f:
        f.write(Key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    ))
        f.close()

    with open(f"out/{Server_name}-KeyPassword.txt", "w") as f:
        f.write(password)
        f.write("\n")
        f.close()

    # Generate certificate for the database
        subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, Server_name),
    ])
        db_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_name
    ).public_key(
        PubKey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year + 1)
    ).sign(CAkey, hashes.SHA256())

    # Wrtie cert to file
    with open(f"out/{Server_name}-Cert.pem", "wb") as f:
        f.write(db_cert.public_bytes(encoding=serialization.Encoding.PEM))
        f.close()

gen_key_cert_signed(ca_name,CAkey, "ca")
gen_key_cert_signed(ca_name,CAkey, "db")
gen_key_cert_signed(ca_name,CAkey, "www")
gen_key_cert_signed(ca_name,CAkey, "fw")
gen_key_cert_signed(ca_name,CAkey, "bkp")

