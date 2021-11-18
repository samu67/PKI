from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
import requests



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

url = "url"

class Credentials(db.Model):
    userID = db.Column(db.String, primary_key=True)
    lastName = db.Column(db.String(20), nullable=True)
    firstName = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(20), nullable=True)
    pwd = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return '<New Credential %r> %self.userID'

class userID_passwdHash(db.Model):
    userID = db.Column(db.String, primary_key=True)
    passwordHash = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<New Credential %r> %self.userID'

class userID_certs(db.Model):
    serialN = db.Column(db.Integer, nullable=False, primary_key=True)
    userID = db.Column(db.String, nullable=False)
    cert = db.Column(db.String(100), nullable=False)
    revoked = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<New Credential %r> %self.userID'

class stats(db.Model):
    nIssuedCerts = db.Column(db.Integer, nullable=False,primary_key=True)
    nRevokedCerts = db.Column(db.Integer, nullable=False)
    currentSN = db.Column(db.Integer, nullable=False)
    def __repr__(self):
        return '<New Credential %r> %self.nIssuedCerts'


@app.route('/', methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        #check for credentials first
        try:
            username = request.form['username']
            password = request.form['password']

            response = requests.post(url+"/login", json={'uid':username, 'pwd':password}).json()

            #userID==Username, username not changable primary key

            #if check pass get user of username and continue
            #need to populate database

            if response['valid']:
                #do some session management
                return redirect('/user/'+username)
            else:
                return render_template('login.html')
            #check if user is admin, if so render admin
        except:
            return 'faild to connect to db'
    elif request.method == 'GET':
        return render_template('login.html')

@app.route('/user/<string:username>', methods=['GET'])
def user(username):
    #i should get everyting form db with the username
    (credentials,certs) = getUserInfo(username)
    return render_template('user.html', user=credentials,certs=certs)

def getUserInfo(username):
    try:
        credentials = requests.get(url+"/credentials", json={'uid':username}).json()
        certs = requests.get(url+"/certificates", json={'uid':username}).json()
        return (credentials,certs)
    except:
        return "faild to connect to db"




@app.route('/updateLastName/<string:username>', methods=['POST'])
def updateLastName(username):
    newLastName = request.form['newLastName']
    try:
        response = requests.post(url+"/credentials", json={'uid':username, 'lastname':newLastName, 'pwd':"",'firsrname':"",'email':""}).json()
        if response == "Success":
            return redirect('/user/username')
        else:
           return "update uncessessfull"
    except:
         return "faild to connect to server"


@app.route('/updateFirstName/<string:username>', methods=['POST'])
def updateFirstName(username):
    newFirstName = request.form['newFirstName']
    try:
        response = requests.post(url+"/credentials", json={'uid':username, 'lastname':"", 'pwd':"",'firsrname':newFirstName,'email':""}).json()
        if response == "Success":
            return redirect('/user/username')
        else:
           return "update uncessessfull"
    except:
         return "faild to connect to server"


@app.route('/updateEmail/<string:username>', methods=['POST'])
def updateEmail(username):
    newEmail = request.form['newEmail']
    try:
        response = requests.post(url+"/credentials", json={'uid':username, 'lastname':"", 'pwd':"",'firsrname':"",'email':newEmail}).json()
        if response == "Success":
            return redirect('/user/username')
        else:
           return "update uncessessfull"
    except:
         return "faild to connect to server"

    return redirect('/user/username')
@app.route('/updatePassword/<string:username>', methods=['POST'])
def updatePassword(username):
    (CRL, certs,user) = getUserInfo(username)
    currentPassword = request.form['currentPassword']
    newPassword0 = request.form['newPassword0']
    newPassword1 = request.form['newPassword1']
    try:
        response = requests.post(url+"/login", json={'uid':username, 'pwd':currentPassword}).json()
        if response['valid']:
            if(newPassword1==newPassword0):
                response = requests.post(url+"/credentials", json={'uid':username, 'lastname':"", 'pwd':newPassword1,'firsrname':"",'email':""}).json()
                if response == "Success":
                    return redirect('/user/username')
                else:
                   return "update uncessessfull"
            else:
                return "please repeate your new password correctly"
        else:
            return "please reenter your current password"
    except:
         return "faild to connect to server"





@app.route('/requestNewCert/<string:username>', methods=['POST'])
def requestNewCert(username):
    try:
        response = requests.post(url+"/certificates", json={'uid':username}).json()
        if response.cert != None:
            return redirect('/user/username')
        else:
            return "faild to issue new cert"
    except:
        return "faild to connect to server"


@app.route('/downloadCrl/<string:username>', methods=['POST'])
def downloadCrl(username):
    try:
        crl = requests.get(url+"/revoked").json()
        return redirect('/user/username')
        #somehow start downloading crl on user page
    except:
        return "faild to connect to db"



@app.route('/logout/<string:username>', methods=['POST'])
def logout(username):
    #do session management, remove current user from curret logged llist, remove session id
    return redirect('/')

@app.route('/revokeCert/<string:username>$<string:serialN>', methods=['POST'])
def revokeCert(username,serialN):
    try:
        response = requests.post(url+"/revoked", json={'uid':username, "serialnumber":serialN}).json()
        if(response["Success"==1]):
            return redirect('/user/username')
        else:
            return "revokation unsuccessfull"
    except:
        return "faild to connect to db"


if __name__ == "__main__":

    #populate db before running

    app.run(debug=True)
