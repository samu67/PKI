import random

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime

#what i had to do
#line17: encode
#line 54: format

class CA:
    def __init__(self, keyfilepath):
        keyfile = open(keyfilepath, "r")
        self.rawkey = keyfile.read()
        keyfile.close()
        self.ca_privatekey = serialization.load_pem_private_key((self.rawkey).encode("utf-8"), password=b"password")
        self.ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
        ])
        inittime = datetime.datetime.utcnow()
        try:
            with open("RevokedSNs.txt", "r")as revsn:
                self.crl = x509.CertificateRevocationListBuilder()
                self.crl = self.crl.issuer_name(self.ca_name)
                self.crl = self.crl.last_update(inittime)
                self.crl = self.crl.next_update(inittime.replace(year=datetime.datetime.utcnow().year + 10))
                serialnumbers  = revsn.readlines()
                with open("CRL.pem", "rb") as crlfile:
                    oldcrl = x509.load_pem_x509_crl()
                    for number in serialnumbers:
                        revokedcert = oldcrl.get_revoked_certificate_by_serial_number(int(number))
                        self.crl = self.crl.add_revoked_certificate(revokedcert)


        except:
            self.crl = x509.CertificateRevocationListBuilder()
            self.crl = self.crl.issuer_name(self.ca_name)
            self.crl = self.crl.last_update(inittime)
            self.crl = self.crl.next_update(inittime.replace(year=datetime.datetime.utcnow().year + 10))
        print("CA: CA initialized", flush=True)
        return

    # Issues certificate.
    # Requires name and password of client who wants the certificate.
    # Returns the issued certificate in pkcs12 format as well as the freshly generated private and public keys of the
    # client as PEM files (the private key is encrypted with the client's password encoded to bytes in utf-8,
    # as is the pkcs12 certificate)
    def issuecert(self, name):
        clientprivkey = ec.generate_private_key(ec.SECP384R1())
        clientkey = clientprivkey.public_key()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        sn = x509.random_serial_number()
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_name
        ).public_key(
            clientkey
        ).serial_number(
            sn
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year+1)
        ).sign(self.ca_privatekey, hashes.SHA256())
        pkcs12cert = pkcs12.serialize_key_and_certificates(name=name.encode("utf-8"), key=clientprivkey, cert=cert, encryption_algorithm=serialization.BestAvailableEncryption(b"A"), cas=None)
        print("CA: Certificate issued for subject " + str(name) + " with serial number " + str(sn), flush=True)
        return pkcs12cert

    # Revokes certificate using information provided by the datatbase (currently we assume the provided data consists of
    # serial number of the certificate to be revoked)
    # Returns serial nr
    def revokecert(self, serialnr):
        revokedcert = x509.RevokedCertificateBuilder().serial_number(
            serialnr
        ).revocation_date(
            datetime.datetime.today()
        ).build()
        self.crl = self.crl.add_revoked_certificate(revokedcert)
        #self.crl = self.crl.last_update(datetime.datetime.utcnow())
        #self.crl = self.crl.next_update(datetime.datetime.utcnow().replace(day=datetime.datetime.utcnow().day+1))
        crlpem = self.crl.sign(private_key=self.ca_privatekey, algorithm=hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        with open("CRL.pem", "wb") as crlfile:
            crlfile.write(crlpem)
        with open("RevokedSNs.txt", "a") as revsn:
            revsn.write(serialnr)
        print("CA: Certificate revoked for serial number " + str(serialnr), flush=True)
        return crlpem


    # Returns current CRL in PEM format
    def getCRL(self):
        print("CA: CRL requested", flush=True)
        return self.crl.sign(private_key=self.ca_privatekey, algorithm=hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
