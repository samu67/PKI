import flask
from CA import CA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


myCA = CA("CAkey.pem")

app = flask.Flask(__name__)
@app.route("/requestCert", methods=["POST"])
def requestCertFromCA():
    return myCA.issuecert(flask.request.json["name"], flask.request.json["pk"])


@app.route("/revokeCert", methods=["POST"])
def revokeCert():
    return myCA.revokecert(flask.request.json["serialnr"])


@app.route("/getCRL")
def getCRLFromCA():
    return myCA.getCRL()
