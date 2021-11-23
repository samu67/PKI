from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import datetime

# Define name attribute of CA
ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
        ])

# Generate signing key of CA
CAkey = ec.generate_private_key(ec.SECP384R1())
with open("CAkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
    f.close()


# The following block is essentially the default way to generate a key-pair and certificate for
# any kind of server. If you need more certificates, just copy this and replace the variable names where necessary,
# the name of the pem file and the name of the subject.
# Generate private and public key of the server
ServerKey = ec.generate_private_key(ec.SECP384R1())
ServerPubKey = ServerKey.public_key()
with open("ServerKey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
    f.close()

# Generate certificate for the Server
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Server"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    ca_name
).public_key(
    ServerPubKey
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year + 1)
).sign(CAkey, hashes.SHA256())





# Generate private and public key of the database
DBkey = ec.generate_private_key(ec.SECP384R1())
DbPubKey = DBkey.public_key()
with open("DBkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
    f.close()

# Generate certificate for the database
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Database"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    ca_name
).public_key(
    ServerPubKey
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year + 1)
).sign(CAkey, hashes.SHA256())
