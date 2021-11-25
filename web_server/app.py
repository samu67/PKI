import hashlib

from flask import Flask, render_template, url_for, request, redirect, session
import requests
from userinput import updateCredentials, SignIn, RevokeCert
import hashlib
from datetime import timedelta



#context = SSL.Context(SSL.TLS1_3_VERSION)
#context.load_cert_chain('/etc/Flask/certs/webserver_cert.pem', '/etc/Flask/private/webserver_key.pem')
#context.verify_mode = SSL.CERT_OPTIONAL
#context.load_verify_locations('/etc/Flask/certs/cacert.pem')


app = Flask(__name__)
app.config['SECRET_KEY'] = '6fd832e3ca1bbd28d7e24aea6d1b66ed'
app.permanent_session_lifetime = timedelta(minutes=5)
db_url = "https://db.imovies.com"


@app.route('/', methods=['POST', 'GET'])
def login():
    form = SignIn()
    if form.validate_on_submit() and request.method == 'POST':
        #check for credentials first
        uid = form.username.data
        password = form.password.data

        password_sh1_hash = hash_pwd(password)
        try:

            # use bcrypt on sha1 hash for better security, needs also change on db

            response = requests.post(db_url + "/login", json={'uid': uid, 'pwd': password_sh1_hash},verify='/home/usr/app/CAPubKey.pem').json()

            if response['valid']:
#            if True:
                #do some session management
                session['uid'] = uid
                session.permanent = True
                return redirect('/user')
            else:
                return render_template('login.html', form=form)
            #check if user is admin, if so render admin
        except:
            return 'failed to connect to db at login'
    elif "uid" in session:
        return redirect(url_for('user'))
    else:
        return render_template('login.html', form=form)


def hash_pwd(password):
    hash_alg = hashlib.sha1()
    hash_alg.update(password.encode())
    password_sh1_hash = hash_alg.hexdigest()
    return password_sh1_hash



@app.route('/user', methods=['GET'])
def user():
    if "uid" in session:
        uid = session["uid"]
        form = updateCredentials()
        revoke = RevokeCert()
        #i should get everyting form db with the username
        (credentials,certs) = getUserInfo(uid)
        return render_template('user.html', credentials=credentials, certs=certs,form=form, revoke=revoke)
    else:
        return redirect(url_for("login"))

def getUserInfo(uid):
    try:
        credentials = requests.get(db_url +"/credentials", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()
        certs = requests.get(db_url +"/certificates", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()
        #credentials = {"uid": "test", "firstname": "test", "lastname":"test", "email":"test"}
        #certs = [("test",123),("test",123)]
        return (credentials , certs)
    except:
        return "failed to connect to db"




@app.route('/updateLastName', methods=['POST'])
def updateLastName():
    form = updateCredentials()
    if form.validate_on_submit and "uid" in session:
        uid = session["uid"]
        newLastName = form.lastname.data

        try:

            response = requests.put(db_url + "/credentials", json={"uid":uid, "lastname":newLastName, "pwd": "", "firstname": "", "email": ""},verify='/home/usr/app/CAPubKey.pem').json()
            if response["Success"] == 1:
                return redirect('/user')
            else:
               return "update unsuccessful"

        except:
             return "failed to connect to server"


@app.route('/updateFirstName', methods=['POST'])
def updateFirstName():
    form = updateCredentials()

    if form.validate_on_submit and "uid" in session:
        uid = session["uid"]
        newFirstName = form.firstname.data

        try:
            response = requests.put(db_url + "/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname':newFirstName, 'email': ""},verify='/home/usr/app/CAPubKey.pem').json()
            if (response["Success"] == 1):
                return redirect('/user')
            else:
               return "update uncessessfull"
        except:
             return "failed to connect to server"


@app.route('/updateEmail', methods=['POST'])
def updateEmail():
    form = updateCredentials()
    if form.validate_on_submit and "uid" in session:
        uid = session["uid"]
        newEmail = form.email.data

        try:
            response = requests.put(db_url + "/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname': "", 'email':newEmail},verify='/home/usr/app/CAPubKey.pem').json()
            if response["Success"] == 1:
                return redirect('/user')
            else:
               return "update uncessessfull"
        except:
             return "failed to connect to server"

    return redirect('/user')
@app.route('/updatePassword', methods=['POST'])
def updatePassword():
    form = updateCredentials()
    if form.validate_on_submit and "uid" in session:
        uid = session["uid"]

        currentPassword = hash_pwd(form.current_password.data)
        newPassword2 = hash_pwd(form.password1.data)
        newPassword1 = hash_pwd(form.password2.data)

        #passowrd eql validator doesn't work, doing it manually for now
        try:
            response = requests.post(db_url + "/login", json={'uid':uid, 'pwd':currentPassword},verify='/home/usr/app/CAPubKey.pem').json()
            if response['valid']:
                if(newPassword1 == newPassword2):
                    response = requests.put(db_url + "/credentials", json={'uid':uid, 'lastname': "", 'pwd':newPassword1, 'firstname': "", 'email': ""},verify='/home/usr/app/CAPubKey.pem').json()
                    if response ["Success"] == 1:
                        return redirect('/user')
                    else:
                       return "update uncessessfull"
                else:
                    return "please repeate your new password correctly"
            else:
                return "please reenter your current password"
        except:
             return "failed to connect to server"





@app.route('/requestNewCert', methods=['POST'])
def requestNewCert():
    if "uid" in session:
        uid = session["uid"]

        try:
            response = requests.post(db_url + "/certificates", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()
            if response["cert"] != None:
                return redirect('/user')
            else:
                return "failed to issue new cert"
        except:
            return "failed to connect to server"


@app.route('/downloadCrl', methods=['POST'])
def downloadCrl():
    if "uid" in session:
        uid = session["uid"]

        try:
            crl = requests.get(db_url + "/revoked",verify='/home/usr/app/CAPubKey.pem')

            filename = "revocation_list.crl"
            response = crl.content
            response.headers.set('Content-Type', 'application/text')
            response.headers.set('Content-Disposition', 'attachment', filename=filename)
            #somehow start downloading crl on user page
            return redirect('/user')
        except:
            return "failed to connect to db"



@app.route('/logout', methods=['POST'])
def logout():
    #do session management, remove current user from curret logged llist, remove session id
    session.pop("uid", None)
    return redirect(url_for("login"))

@app.route('/revokeCert/<string:serialN>', methods=['POST'])
def revokeCert(serialN):
    if "uid" in session:
        uid = session["uid"]
        #does db check if sn belongs to uid before revoking/ tranfering to ca
        try:
            response = requests.put(db_url + "/revoked", json={'uid':uid, "serialnumber":serialN},verify='/home/usr/app/CAPubKey.pem').json()
            if(response["Success"]==1):
                return redirect('/user')
            else:
                return "revokation unsuccessful"
        except:
            return "failed to connect to db"


if __name__ == "__main__":

    app.run(debug=True)
