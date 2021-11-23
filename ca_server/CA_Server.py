import flask
from CA import CA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CAkey = ec.generate_private_key(ec.SECP384R1())
with open("CAkey.pem", "wb") as f:
    f.write(CAkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    ))

myCA = CA("CAkey.pem")

app = flask.Flask(__name__)
@app.route("/requestCert", methods=["POST"])
def requestCertFromCA():
    return myCA.issuecert(flask.request.json["uid"])


@app.route("/revokeCert", methods=["POST"])
def revokeCert():
    return myCA.revokecert(flask.request.json["serialnr"])


@app.route("/getCRL")
def getCRLFromCA():
    return myCA.getCRL()
