from cryptography.fernet import Fernet
import bcrypt
import base64
from app import db
from db import users, userID_certs, userID_passwdHash, stats, CA_admins



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

def gencertkey():
    #todo generates the key
    key = Fernet.generate_key()
    try:
    	with open("dbkey.txt", 'rb') as f:
    	 pass
    except:
    	with open("dbkey.txt", 'wb') as f:
        	f.write(key)



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

def encryptcerts():    
    certs = userID_certs.query.all()
    for cert in certs:
        enccert = encryptcert(cert.cert)
        	#make sure my cert operations are reversible
        assert (cert.cert == decryptcert(enccert))
        cert.cert = enccert
    db.session.commit()


def rehash():
    #todo hash the sha1 in the original db to bcrypt
    match = users.query.all()
    for user in match:
        hashed = bcrypt.hashpw((user.pwd).encode("utf-8"), bcrypt.gensalt())
        assert (bcrypt.checkpw((user.pwd).encode("utf-8").decode("utf-8").encode("utf-8") , hashed))
        user.pwd = hashed.decode("utf=8")
        print(user.uid + " " + user.pwd)
    db.session.commit()

gencertkey()
reset_db()
#encryptcerts()
rehash()
