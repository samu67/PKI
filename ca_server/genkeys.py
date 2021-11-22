from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


CAkey = ec.generate_private_key(ec.SECP384R1())
with open("CAkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
f.close()

ServerKey = ec.generate_private_key(ec.SECP384R1())
with open("ServerKey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
f.close()

DBkey = ec.generate_private_key(ec.SECP384R1())
with open("DBkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))
f.close()
