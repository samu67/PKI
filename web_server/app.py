import hashlib

from flask import Flask, render_template, url_for, request, redirect, session
import requests
from userinput import updateCredentials, SignIn, RevokeCert
import hashlib
from datetime import timedelta
from flask import send_file,Response
import base64
from cryptography.hazmat.primitives.serialization import pkcs12

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

    if "uid" in session:
        return redirect(url_for('user'))
    elif 'CLIENT_CERT' in request.environ and request.environ.get('CLIENT_CERT') != "":
        print(request.environ.get('CLIENT_CERT'))
        s_dn = request.environ.get('CLIENT_CERT')
        uid = s_dn.split('=')[1] 
        session['uid'] = uid
        session['certAuth'] = 1
        session.permanent = True
        print('{uid} has logged in with a certificate'.format(uid=uid), flush=True)
        return redirect(url_for('user'))
    else:
        form = SignIn()
        if form.validate_on_submit() and request.method == 'POST':
            uid = form.username.data
            password = form.password.data
            password_sh1_hash = hash_pwd(password)
            try:
                # use bcrypt on sha1 hash for better security, needs also change on db
                response = requests.post(db_url + "/login", json={'uid': uid, 'pwd': password_sh1_hash}, verify='/home/usr/app/CAPubKey.pem').json()
                if response['valid']:
                    session['uid'] = uid
                    session['certAuth'] = 0
                    session.permanent = True
                    print('{uid} has logged in with password'.format(uid=uid), flush=True)
                    return redirect(url_for('user'))
                else:
                    print('Login attempt for uid: {uid} with wrong password'.format(uid=uid), flush=True)
                    return render_template('login.html', form=form)
            except:
                print('failed to connect to db at login', flush=True)
                return 'failed to connect to db at login'
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
        (credentials, certs) = getUserInfo(uid)
        if credentials["isAdmin"] == 1 and session['certAuth'] == 1:
            session["isAdmin"] = 1
            stats = requests.get(db_url +'/certificate_stats',verify='/home/usr/app/CAPubKey.pem').json()
            return render_template('admin.html', credentials=credentials, certs=certs, form=form, revoke=revoke, stats=stats)
        else:
           session["isAdmin"] = 0
           return render_template('user.html', credentials=credentials, certs=certs,form=form, revoke=revoke)
    else:
        return redirect(url_for("login"))

def getUserInfo(uid):
    try:
        credentials = requests.get(db_url +"/credentials", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()
        certs = requests.get(db_url +"/certificates", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()

        #credentials = {"uid": "test", "firstname": "test", "lastname":"test", "email":"test", "isAdmin": 1}

        #for loop over all pk12 to build list of tupples
        #i also need a list containg only the serial number a user owns, can revoke, download. save this in session
        #certs = [("serial_number","not_valid_before","not_valid_after","pk12"),
        #         ("serial_number","not_valid_before","not_valid_after", "pk12" ),
        #         ("serial_number","not_valid_before","not_valid_after","pk12"),
        #         ("serial_number","not_valid_before","not_valid_after","pk12")]
        #usersSNs = ["serial_number","serial_number","serial_number","serial_number"]
        #session["usersSNs"] = usersSNs

        certinfo=[]
        usersSNs = []
        for cert in certs["certs"]:
            encodedbytes = cert[0]
            decodedbytes = base64.urlsafe_b64decode(encodedbytes)
        	# senc decodedbytes to client, he can then load it with pkcs12.load_key_and_certificates
            (current_key, current_cert, _) = pkcs12.load_key_and_certificates(decodedbytes, b"A")
            nvb = str(current_cert.not_valid_before)
            nva = str(current_cert.not_valid_after)
            sn= str(current_cert.serial_number)
            print(f"sn: {str(current_cert.serial_number)}", flush=True)
            certinfo.append((sn, nvb, nva, decodedbytes))
            usersSNs.append(sn)
        session["usersSNs"] = usersSNs
        return (credentials , certinfo)
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
                print('user: {uid} has updated lastname to {newLastName}'.format(uid=uid, newLastName=newLastName), flush=True)
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
                print('user: {uid} has updated firstname to {newFirstName}'.format(uid=uid, newFirstName=newFirstName), flush=True)
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
                print('user: {uid} has updated lastname to {newEmail}'.format(uid=uid, newEmail=newEmail), flush=True)
                return redirect('/user')
            else:
               return "update uncessessfull"
        except:
             return "failed to connect to server"

    return redirect('/user')
@app.route('/updatePassword', methods=['POST'])
def updatePassword():
    form = updateCredentials()
    if form.validate_on_submit and "uid" in session and session["isAdmin"] == 0:
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
                    if response["Success"] == 1:
                        print('user: {uid} has updated password', flush=True)
                        return redirect('/user')
                    else:
                       return "update uncessessfull"
                else:
                    return "please repeate your new password correctly"
            else:
                print('unsuccessfully attempt to update password of user: {uid} '.format(uid=uid), flush=True)
                return "please reenter your current password"
        except:
             return "failed to connect to server"





@app.route('/requestNewCert/<string:uid>', methods=['POST'])
def requestNewCert(uid):
    if "uid" in session:
        uid = session["uid"]

    #if user is logged in uid will be user's uid, else uid will be userinput string.

    try:
        response = requests.post(db_url + "/certificates", json={'uid':uid},verify='/home/usr/app/CAPubKey.pem').json()
        if response["cert"] != None:
            print('user: {uid} has requested new certificate'.format(uid=uid), flush=True)
            #return redirect('/user')
            decodedbytes = base64.urlsafe_b64decode( response["cert"])

            return Response(
                decodedbytes ,
                mimetype="application/octet-stream",
                headers={"Content-disposition":
                 "attachment; filename= certificate.p12"})

        else:
            return "failed to issue new cert"
    except:
        return "failed to connect to server"


@app.route('/downloadCrl', methods=['POST'])
def downloadCrl():
    if "uid" in session:
        try:
            crl = requests.get(db_url + "/revoked",verify='/home/usr/app/CAPubKey.pem')
            #crl = "MIIDrwIBAzCCA3kGCSqGSIb3DQEHAaCCA2oEggNmMIIDYjCCAg8GCSqGSIb3DQEHBqCCAgAwggH8AgEAMIIB9QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIYZU_arf_l7cCAk4ggIIByDSliGxVa1o6Mkv8kwn2l34z_WlRtQ30BOTLqbQADcX6SL7x6_eFAbqazZ3OQ4v8DANblTwCxlufM6ZPv-WfvZvYHTBEM0eaUAFhTC24jQ1oQl59Sd5ClD_7WuMN66VMvfqiuckDNkb3qK8rtQHR3XzTZ5BqgVzBFCSzmLKXneo7yjBb3oFuf7uQj6R3kDLih3EUgAm5SQOTfkY5po8wn_ZyMrM7J3wagk40u238EdOqw0676sfUQ2654Slsfi9eGo0oTucvMFdN2ILVZ3OtCjjjuqMJXOPAoBi1YV_IHrZmEDEyg_ZY72AfeoL2XadEzTX7_1horG1uB8PVyiumYDgzByW3JOQ9Ynhrp91LKRM5Z2s_InI6lkjT0uBYz9PKcl7F9EhTq3h8XF0R5B25XP-ODApnrvEdBIljEEckmxAfWa4vpY0ByrK5otjmR3yhoqju8r5WiAnJGmjny2FzIs9RhEOcdPby0q2uH9xj11z-bI6nas44EZkbRPuVmCH6cKFCM0piGNehlIQXny8fQW3KWq6EQBvaJVtEHIXq7WpFFs2vLEmIiwPVkCQtG7wMTQ2JQUM-iQc-Q1psb5mNkMFuUvUH_2aGbDCCAUsGCSqGSIb3DQEHAaCCATwEggE4MIIBNDCCATAGCyqGSIb3DQEMCgECoIHkMIHhMBwGCiqGSIb3DQEMAQMwDgQI4toqSbQcYTICAk4gBIHAw7HZSMDZB7ymgjnG3p9HQkNKyZBWUnzNd3pcDUuxhnwC6A69SP46XOp5ZP5FBjKhwbpgfSrfebEQUHN00zOe1rlNfKLqHjC8Cd1_0J9OPlRnjJg29u4FmtPNJCmlOLqWXWErhkX-umSRC5heEJltQMbCKubwKjT2sKJ7pst0g3nfVlh-_iUFOVBA52KC0j-EUji0eTyMY849OkSNKy6-O9UOo4obcLj4YZIcs2piVMM-eDutOWeAnRgOxkmstac2MTowEwYJKoZIhvcNAQkUMQYeBABhADMwIwYJKoZIhvcNAQkVMRYEFN7QVsGf1MfbKabtVbDJnlfV8d7wMC0wITAJBgUrDgMCGgUABBRjqfgYrJxI36vGIYPlxx_AtIxzQgQIjoMa_SAo0RA="
            return Response(
                crl,
                mimetype="application/octet-stream",
                headers={"Content-disposition":
                         "attachment; filename= crl.pem"})
            #somehow start downloading crl on user page
        except:
            return "failed to connect to db"



@app.route('/logout', methods=['POST'])
def logout():

    #do session management, remove current user from curret logged llist, remove session id
    session.pop("uid", None)
    session.pop('certAuth', None)
    session.pop('isAdmin', None)
    session.pop("usersSNs", None)
    session.clear()

    return redirect(url_for("login"))

@app.route('/revokeCert/<string:serialN>', methods=['POST'])
def revokeCert(serialN):
    if "uid" in session and "usersSNs" in session and serialN in session["usersSNs"]:
        uid = session["uid"]
        try:
            response = requests.put(db_url + "/revoked", json={'uid':uid, "serialnumber":serialN},verify='/home/usr/app/CAPubKey.pem')
            crl = response.content
            with open("/home/usr/app/crl.pem","wb") as f:
                f.write(crl)
            print(f'{uid} has revoked cert: {serialN}'.format(uid=uid, serialN=serialN), flush=True)
            return redirect('/user')
        except:
            return "failed to connect to db"

@app.route('/downloadPK12/<string:serialN>', methods=['GET'])
def downloadPK12(serialN):
    if "uid" in session and "usersSNs" in session and serialN in session["usersSNs"]:
        (credentials , certs) = getUserInfo(uid=session["uid"])
        #iterate over certs to find pk12 corresponding to seriralN
        #pk12 = "MIIDrwIBAzCCA3kGCSqGSIb3DQEHAaCCA2oEggNmMIIDYjCCAg8GCSqGSIb3DQEHBqCCAgAwggH8AgEAMIIB9QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIYZU_arf_l7cCAk4ggIIByDSliGxVa1o6Mkv8kwn2l34z_WlRtQ30BOTLqbQADcX6SL7x6_eFAbqazZ3OQ4v8DANblTwCxlufM6ZPv-WfvZvYHTBEM0eaUAFhTC24jQ1oQl59Sd5ClD_7WuMN66VMvfqiuckDNkb3qK8rtQHR3XzTZ5BqgVzBFCSzmLKXneo7yjBb3oFuf7uQj6R3kDLih3EUgAm5SQOTfkY5po8wn_ZyMrM7J3wagk40u238EdOqw0676sfUQ2654Slsfi9eGo0oTucvMFdN2ILVZ3OtCjjjuqMJXOPAoBi1YV_IHrZmEDEyg_ZY72AfeoL2XadEzTX7_1horG1uB8PVyiumYDgzByW3JOQ9Ynhrp91LKRM5Z2s_InI6lkjT0uBYz9PKcl7F9EhTq3h8XF0R5B25XP-ODApnrvEdBIljEEckmxAfWa4vpY0ByrK5otjmR3yhoqju8r5WiAnJGmjny2FzIs9RhEOcdPby0q2uH9xj11z-bI6nas44EZkbRPuVmCH6cKFCM0piGNehlIQXny8fQW3KWq6EQBvaJVtEHIXq7WpFFs2vLEmIiwPVkCQtG7wMTQ2JQUM-iQc-Q1psb5mNkMFuUvUH_2aGbDCCAUsGCSqGSIb3DQEHAaCCATwEggE4MIIBNDCCATAGCyqGSIb3DQEMCgECoIHkMIHhMBwGCiqGSIb3DQEMAQMwDgQI4toqSbQcYTICAk4gBIHAw7HZSMDZB7ymgjnG3p9HQkNKyZBWUnzNd3pcDUuxhnwC6A69SP46XOp5ZP5FBjKhwbpgfSrfebEQUHN00zOe1rlNfKLqHjC8Cd1_0J9OPlRnjJg29u4FmtPNJCmlOLqWXWErhkX-umSRC5heEJltQMbCKubwKjT2sKJ7pst0g3nfVlh-_iUFOVBA52KC0j-EUji0eTyMY849OkSNKy6-O9UOo4obcLj4YZIcs2piVMM-eDutOWeAnRgOxkmstac2MTowEwYJKoZIhvcNAQkUMQYeBABhADMwIwYJKoZIhvcNAQkVMRYEFN7QVsGf1MfbKabtVbDJnlfV8d7wMC0wITAJBgUrDgMCGgUABBRjqfgYrJxI36vGIYPlxx_AtIxzQgQIjoMa_SAo0RA="
        pk12="Error"
        for cert in certs:
            (sn,_,_,certbytes) = cert
            print(str(sn) +" "+ str(serialN), flush=True)
            if (sn==serialN):
                pk12=certbytes
    return Response(
        pk12,
        mimetype="application/octet-stream",
        headers={"Content-disposition":
                 "attachment; filename= certificate.p12"})




if __name__ == "__main__":

    app.run(debug=True)
