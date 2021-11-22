import flask
import base64
from CA import CA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

myCA = CA()

app = flask.Flask(__name__)
@app.route("/requestCert", methods=["POST"])
def requestCertFromCA():
    print(flask.request.json)
    print(flask.request.json["pk"].encode("utf-8"))
    return myCA.issuecert(flask.request.json["uid"], (flask.request.json["pk"]).encode("utf-8"))


@app.route("/revokeCert", methods=["POST"])
def revokeCert():
    return myCA.revokecert(flask.request.json["serialnumber"])


@app.route("/getCRL")
def getCRLFromCA():
    return myCA.getCRL()
