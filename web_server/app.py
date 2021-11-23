import hashlib
import base64


from flask import Flask, render_template, url_for, request, redirect, session
import requests
from userinput import updateCredentials, SignIn, RevokeCert
import hashlib
from datetime import timedelta
from cryptography.hazmat.primitives.serialization import pkcs12



#context = SSL.Context(SSL.TLS1_3_VERSION)
#context.load_cert_chain('/etc/Flask/certs/webserver_cert.pem', '/etc/Flask/private/webserver_key.pem')
#context.verify_mode = SSL.CERT_OPTIONAL
#context.load_verify_locations('/etc/Flask/certs/cacert.pem')


app = Flask(__name__)
app.config['SECRET_KEY'] = '6fd832e3ca1bbd28d7e24aea6d1b66ed'
app.permanent_session_lifetime = timedelta(minutes=5)
db_url = "http://127.0.0.1:5000"


@app.route('/', methods=['POST', 'GET'])
def login():
    form = SignIn()

    if form.validate_on_submit() and request.method == 'POST':
        #check for credentials first
        uid = form.username.data
        password = form.password.data

        hash_alg = hashlib.sha1()
        hash_alg.update(password.encode())
        password_sh1_hash = hash_alg.hexdigest()
        try:

            #use bcrypt on sha1 hash for better security, needs also change on db

            response = requests.post(db_url + "/login", json={'uid': uid, 'pwd': password_sh1_hash}).json()

            if response['valid']:

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

@app.route('/user', methods=['GET'])
def user():
    if "uid" in session:
        uid = session["uid"]
        form = updateCredentials()
        revoke = RevokeCert()
        #i should get everyting form db with the username
        (credentials,certs) = getUserInfo(uid)


        #encodedbytes = certs["certs"][0][0]
        #decodedbytes = base64.urlsafe_b64decode(encodedbytes)
        # senc decodedbytes to client, he can then load it with pkcs12.load_key_and_certificates
        #(current_key, current_cert, _) = pkcs12.load_key_and_certificates(decodedbytes, b"A")
        #test = current_cert.subject

        return render_template('user.html', credentials=credentials, certs=certs,form=form, revoke=revoke)
    else:
        return redirect(url_for("login"))

def getUserInfo(uid):
    try:
        credentials = requests.get(db_url +"/credentials", json={'uid':uid}).json()
        certs = requests.get(db_url +"/certificates", json={'uid':uid}).json()
        #credentials = {"uid": "test", "firstname": "test", "lastname":"test", "email":"test"}
        #certs = [("test",123),("test",123)]
        #certs = {"certs":certs}
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

            response = requests.put(db_url + "/credentials", json={"uid":uid, "lastname":newLastName, "pwd": "", "firstname": "", "email": ""}).json()
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
            response = requests.put(db_url + "/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname':newFirstName, 'email': ""}).json()
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
            response = requests.put(db_url + "/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname': "", 'email':newEmail}).json()
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

        currentPassword = form.current_password.data
        newPassword2 = form.password1.data
        newPassword1 = form.password2.data


        #passowrd eql validator doesn't work, doing it manually for now
        try:
            hash_alg = hashlib.sha1()
            hash_alg.update(currentPassword.encode())
            password_sh1_hash = hash_alg.hexdigest()
            response = requests.post(db_url + "/login", json={'uid':uid, 'pwd':password_sh1_hash}).json()
            if response['valid']:

                if(newPassword1 == newPassword2):
                    new_hash_alg = hashlib.sha1()
                    new_hash_alg.update(newPassword1.encode())
                    new_password_sh1_hash = new_hash_alg.hexdigest()
                    response = requests.put(db_url + "/credentials", json={'uid':uid, 'lastname': "", 'pwd':new_password_sh1_hash, 'firstname': "", 'email': ""}).json()
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
            response = requests.post(db_url + "/certificates", json={'uid':uid}).json()
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
            crl = requests.get(db_url + "/revoked")

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
            response = requests.put(db_url + "/revoked", json={'uid':uid, "serialnumber":serialN}).json()
            if(response["Success"]==1):
                return redirect('/user')
            else:
                return "revokation unsuccessful"
        except:
            return "failed to connect to db"


if __name__ == "__main__":

    app.run(debug=True)
