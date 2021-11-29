from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from secrets import token_urlsafe
import datetime


ca_key_password = token_urlsafe(32)

# Define name attribute of CA
ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
        ])

# Generate signing key of CA
CAkey = ec.generate_private_key(ec.SECP384R1())
with open("out/_CAkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_key_password.encode()),
    ))
    f.close()

with open(f"out/_CAKeyPassword.txt", "w") as f:
    f.write(ca_key_password)
    f.write("\n")
    f.close()

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

def gen_key_cert_signed(ca_name, CAkey, Server_name, encrypt=True, password=None):

    if password == None:
        password = token_urlsafe(32)
    
    # Generate private and public key
    Key = ec.generate_private_key(ec.SECP384R1())
    PubKey = Key.public_key()

    if encrypt:
        enc = serialization.BestAvailableEncryption(password.encode())
    else:
        enc = serialization.NoEncryption()

    with open(f"out/{Server_name}-Key.pem", "wb") as f:
        f.write(Key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc,
    ))
        f.close()

    if encrypt:
        with open(f"out/{Server_name}-KeyPassword.txt", "w") as f:
            f.write(password)
            f.write("\n")
            f.close()

    # Generate certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, Server_name + ".imovies.com"),
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

gen_key_cert_signed(ca_name,CAkey, "ca", encrypt=False)
gen_key_cert_signed(ca_name,CAkey, "db", encrypt=False)
gen_key_cert_signed(ca_name,CAkey, "www", encrypt=False)
gen_key_cert_signed(ca_name,CAkey, "fw", encrypt=False)
gen_key_cert_signed(ca_name,CAkey, "bkp", encrypt=False)

