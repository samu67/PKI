from flask_sqlalchemy import SQLAlchemy
from app import db



class users(db.Model):
    uid = db.Column(db.String(20), primary_key=True)
    lastname = db.Column(db.String(20), nullable=True)
    firstname = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(20), nullable=True)
    pwd = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return '<New Credential %r> %self.userID'

class CA_admins(db.Model):
    uid = db.Column(db.String(20), primary_key=True)


class userID_passwdHash(db.Model):
    uid = db.Column(db.String(20), primary_key=True)
    passwordHash = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<New Credential %r> %self.userID'

class userID_certs(db.Model):
    serialnumber = db.Column(db.String(255), primary_key=True)
    uid = db.Column(db.String(20), nullable=False)
    cert = db.Column(db.Text, nullable=False)
    revoked = db.Column(db.Boolean, nullable=False)
    def __repr__(self):
        return '<New Credential %r> %self.userID'

class stats(db.Model):
    nIssuedCerts = db.Column(db.Integer, nullable=False)
    nRevokedCerts = db.Column(db.Integer, nullable=False)
    currentSN = db.Column(db.String(255), primary_key=True)
    def __repr__(self):
        return '<New Credential %r> %self.nIssuedCerts'
