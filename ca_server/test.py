import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import json
import base64

def test():
    serverpath = "http://127.0.0.1:6000"
    clientkey = ec.generate_private_key(ec.SECP384R1())
    certrequest = {"name": u"client1",
                   "pk": (clientkey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode("utf-8")
                   }
    print(certrequest)
    jsonheader = {"content-type": "application/json"}
    r1 = requests.post((serverpath+"/requestCert"), data=json.dumps(certrequest), headers=jsonheader)
    print(r1.content)
    cert = x509.load_pem_x509_certificate(r1.content)
    revokerequest  = {"serialnr": cert.serial_number}
    r2 = requests.post((serverpath+"/revokeCert"), data=json.dumps(revokerequest), headers=jsonheader)
    r3 = requests.get(serverpath+"/getCRL")
    crl = x509.load_pem_x509_crl(r3.content)

    print(cert.public_bytes(encoding=serialization.Encoding.PEM))
    print(cert.serial_number, cert.subject)
    print(crl.public_bytes(encoding=serialization.Encoding.PEM))
    print(crl.issuer, crl.last_update)
    return 0

if __name__ == "__main__":
    test()