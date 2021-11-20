import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import json


def test():
    serverpath = "localhost:5000"
    clientkey = ec.generate_private_key(ec.SECP384R1())
    certrequest = {"name": u"client1",
                   "pk": clientkey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.Raw)
                   }
    r1 = requests.post((serverpath+"/requestCert"), data=json.dumps(certrequest))
    cert = x509.load_pem_x509_certificate(r1.content)
    revokerequest  = {"serialnr": cert.serial_number}
    r2 = requests.post((serverpath+"/revokeCert"), data=json.dumps(revokerequest))
    r3 = requests.get(serverpath+"/getCRL")
    crl = x509.load_pem_x509_crl(r3.content)

    print(cert)
    print(crl)
    return 0

if __name__ == "__main__":
    test()