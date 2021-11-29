import json

from flask import Flask, request, send_file
from flask_sqlalchemy import SQLAlchemy
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
import base64
from cryptography import x509
from cryptography.fernet import Fernet
import bcrypt
import base64

app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test3.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:WYN98h2oNBDM4pwpnHXpPJczhiVoktEhaPaB8owuWuj6zh2ThfpBdpp@localhost/imovies'
#app.config['SECRET_KEY'] = 'password'
db = SQLAlchemy(app)
from db import users, userID_certs, userID_passwdHash, stats, CA_admins
CA_SERVER = "https://ca.imovies.com/"
CA_SERVER_CRL= ""

@app.route('/')
def debug():  # put application's code here
    return 'debug'

@app.route('/login', methods=['POST'])
def login():  # put application's code here
    #given user and password, check db if match, return true or fals
    content = request.get_json()
    provided_user = content["uid"]
    provided_password = content["pwd"]
    #todo bcrypt
    match = users.query.filter_by(uid = provided_user).first()
    hashedpwd= match.pwd.encode("utf-8")
    valid = bcrypt.checkpw(provided_password.encode("utf-8"), hashedpwd)
    data = {"uid": provided_user, "valid": valid} # Your data in JSON-serializable type
    return data

@app.route('/credentials',methods=['GET', 'PUT'])
def credentials():  # put application's code here
    #GET: show user credentials
    if request.method == 'GET':
        content = request.get_json()
        provided_user = content["uid"]
        match = users.query.filter_by(uid = provided_user).first()
        adminmatch = CA_admins.query.filter_by(uid = provided_user).all()
        isAdmin = 0
        if(len(adminmatch) == 1):
            isAdmin=1
        data = {"uid": match.uid, "firstname": match.firstname, "lastname":match.lastname, "email":match.email, "isAdmin":isAdmin}
        return data
    #PUT: Update user credentials
    else:
        content = request.get_json()
        provided_user = content["uid"]
        provided_password = content["pwd"]
        provided_lastname = content["lastname"]
        provided_firstname =content["firstname"]
        provided_email = content["email"]
        match = users.query.filter_by(uid = provided_user).first()
        if(provided_firstname != ""):
            match.firstname = provided_firstname
        if(provided_lastname != ""):
            match.lastname = provided_lastname
        if(provided_email != ""):
            match.email = provided_email
        if(provided_password != ""):
            match.pwd = bcrypt.hashpw((provided_password).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.session.commit()
        data = {"Success": 1}
        return data

@app.route('/certificates', methods=['GET', 'POST'])
def certificates():  # put application's code here
    #GET: certificates of user
    if request.method == 'GET':
        content = request.get_json()
        provided_user = content["uid"]
        matches = userID_certs.query.filter_by(uid = provided_user, revoked=False).all()
        certs=[]
        for match in matches:
            #todo fernet
            certs.append((decryptcert(match.cert), match.serialnumber))
        #does not return user
        data = {"certs": certs}
        return data

    #POST: A new Certificate for that user
    else:
        #parse
        content = request.get_json()
        provided_user = content["uid"]

        #pass on to ca
        dummykey = ec.generate_private_key(ec.SECP384R1())
        r = requests.post(CA_SERVER+"requestCert", json={"uid": provided_user},verify='/home/usr/app/CAPubKey.pem')
        (key, new_cert, _) = pkcs12.load_key_and_certificates(r.content, b'A')
        #parse again
        SN = new_cert.serial_number
        #new_cert = "TESTCERTIFICATE"

        #update cert database
        #have to find new serial number
        #possible race condition?
        match = stats.query.all()[0]
        match.nIssuedCerts +=1
        #str function would convert bigint to scientific notation
        stringSN = f'{SN}'
        match.currentSN = stringSN
        #todo later
        b64cert = base64.urlsafe_b64encode(r.content).decode("ASCII")
        #todo fernet
        new_cert_entry = userID_certs(serialnumber = stringSN , uid=provided_user, cert=encryptcert(b64cert), revoked=False)
        db.session.add(new_cert_entry)
        db.session.commit()

        #encode when it arrives

        data = {"uid":provided_user,"cert": b64cert, "serialnumber": SN}
        return data


@app.route('/revoked', methods=['GET','PUT'])
def revoked():  # put application's code here
    #GET: Receive the CRL
    if request.method == 'GET':

        r = requests.get(CA_SERVER+"getCRL",verify='/home/usr/app/CAPubKey.pem')
        crl = r.content



        #note this is flask request, not python requestS
        #not sure if the type is correct
        return crl

    #PUT: Revoke a cert for that user
    else:
        #test
        content = request.get_json()
        provided_user = content["uid"]
        provided_SN = int(content["serialnumber"])
        jsonheader = {"content-type": "application/json"}
        jsondata ={"serialnr": provided_SN}
        r = requests.post(CA_SERVER+"revokeCert", headers=jsonheader, data=json.dumps(jsondata),verify='/home/usr/app/CAPubKey.pem')
        if True:
        #if r.status_code == requests.codes.ok:
            certmatch = userID_certs.query.filter_by(uid = provided_user, serialnumber=provided_SN, revoked=False).first()
            certmatch.revoked=True
            statmatch = stats.query.all()[0]
            statmatch.nRevokedCerts +=1
            db.session.commit()
        return r.content

@app.route('/certificate_stats', methods=['GET'])
def get_Certificate_Stats():  # put application's code here
    match = stats.query.all()[0]
    data={"CurrentSN": match.currentSN, "nIssuedCerts": match.nIssuedCerts, "nRevokedCerts": match.nRevokedCerts}
    return data

def reset_db(): 
    db.session.rollback()
    usermatch= users.query.all()
    for user in usermatch:
        db.session.delete(user)

    certmatch= userID_certs.query.all()
    for cert in certmatch:
        db.session.delete(cert)

    adminmatch= CA_admins.query.all()
    for admin in adminmatch:
        db.session.delete(admin)

    statmatch= stats.query.all()
    for stat in statmatch:
        db.session.delete(stat)    

    db.session.commit()
    
    userlist = [users(uid="lb", lastname="Bruegger", firstname="Lukas", email="lb@movies.ch", pwd="8d0547d4b27b689c3a3299635d859f7d50a2b805"),
              users(uid="ps", lastname="Schaller", firstname="Patrick", email="ps@movies.ch", pwd="6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7"),
              users(uid="ms", lastname="Schlaepfer", firstname="Michael", email="ms@movies.ch", pwd="4d7de8512bd584c3137bb80f453e61306b148875"),
              users(uid="a3", lastname="Anderson", firstname="Andres Alan", email="and@movies.ch", pwd="6b97f534c330b5cc78d4cc23e01e48be3377105b"),
              ]
    #        user = db.Credentials(userID="", lastName ="",firstName="", email="", pwd="")
    for user in userlist:
        db.session.add(user)

    admin =CA_admins(uid="a3")
    db.session.add(admin)

    initialstats = stats(nIssuedCerts=0,nRevokedCerts=0,currentSN=0)
    db.session.add(initialstats)

    db.session.commit()
    
    return "Success"


def encryptcert(cert):
    with open("dbkey.txt", 'rb') as f:
        key = f.read()
    c = Fernet(key)
    enccert = c.encrypt((cert.encode('utf-8'))).decode("utf-8")
    return enccert


def decryptcert(cert):
    with open("dbkey.txt", 'rb') as f:
        key = f.read()
    c = Fernet(key)
    deccert = (c.decrypt(cert.encode('utf-8'))).decode('utf-8')
    return deccert


if __name__ == '__main__':

    app.run()
