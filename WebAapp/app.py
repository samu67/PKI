from flask import Flask, render_template, url_for, request, redirect

import requests



app = Flask(__name__)


url = "http://127.0.0.1:5000"


@app.route('/', methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        #check for credentials first
        try:
            uid = request.form['username']
            password = request.form['password']

            response = requests.post(url+"/login", json={'uid': uid, 'pwd': password}).json()

            #userID==Username, username not changable primary key

            #if check pass get user of username and continue
            #need to populate database

            if response['valid']:
                #do some session management
                return redirect('/user/'+uid)
            else:
                return render_template('login.html')
            #check if user is admin, if so render admin
        except:
            return 'failed to connect to db'
    elif request.method == 'GET':
        return render_template('login.html')

@app.route('/user/<string:uid>', methods=['GET'])
def user(uid):
    #i should get everyting form db with the username
    (credentials,certs) = getUserInfo(uid)
    return render_template('user.html', credentials=credentials, certs=certs)

def getUserInfo(uid):
    try:
        credentials = requests.get(url +"/credentials", json={'uid':uid}).json()
        certs = requests.get(url +"/certificates", json={'uid':uid}).json()
        return (credentials , certs)
    except:
        return "failed to connect to db"




@app.route('/updateLastName/<string:uid>', methods=['POST'])
def updateLastName(uid):
    newLastName = request.form['newLastName']
    try:

        response = requests.put(url +"/credentials", json={"uid":uid, "lastname":newLastName, "pwd": "", "firstname": "", "email": ""}).json()
        if response["Success"] == 1:
            return redirect('/user/'+uid)
        else:
           return "update unsuccessful"

    except:
         return "failed to connect to server"


@app.route('/updateFirstName/<string:uid>', methods=['POST'])
def updateFirstName(uid):
    newFirstName = request.form['newFirstName']
    try:
        response = requests.put(url +"/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname':newFirstName, 'email': ""}).json()
        if (response["Success"] == 1):
            return redirect('/user/'+uid)
        else:
           return "update uncessessfull"
    except:
         return "failed to connect to server"


@app.route('/updateEmail/<string:uid>', methods=['POST'])
def updateEmail(uid):
    newEmail = request.form['newEmail']
    try:
        response = requests.put(url +"/credentials", json={'uid': uid, 'lastname': "", 'pwd': "", 'firstname': "", 'email':newEmail}).json()
        if response["Success"] == 1:
            return redirect('/user/'+uid)
        else:
           return "update uncessessfull"
    except:
         return "failed to connect to server"

    return redirect('/user/uid')
@app.route('/updatePassword/<string:uid>', methods=['POST'])
def updatePassword(uid):

    currentPassword = request.form['currentPassword']
    newPassword0 = request.form['newPassword0']
    newPassword1 = request.form['newPassword1']
    try:
        response = requests.post(url +"/login", json={'uid':uid, 'pwd':currentPassword}).json()
        if response['valid']:
            if(newPassword1==newPassword0):
                response = requests.put(url +"/credentials", json={'uid':uid, 'lastname': "", 'pwd':newPassword1, 'firstname': "", 'email': ""}).json()
                if response ["Success"] == 1:
                    return redirect('/user/'+uid)
                else:
                   return "update uncessessfull"
            else:
                return "please repeate your new password correctly"
        else:
            return "please reenter your current password"
    except:
         return "failed to connect to server"





@app.route('/requestNewCert/<string:uid>', methods=['POST'])
def requestNewCert(uid):
    try:
        response = requests.post(url +"/certificates", json={'uid':uid}).json()
        if response["cert"] != None:
            return redirect('/user/'+uid)
        else:
            return "failed to issue new cert"
    except:
        return "failed to connect to server"


@app.route('/downloadCrl/<string:uid>', methods=['POST'])
def downloadCrl(uid):
    try:
        crl = requests.get(url+"/revoked")
        return redirect('/user/'+uid)
        #somehow start downloading crl on user page
    except:
        return "failed to connect to db"



@app.route('/logout/<string:uid>', methods=['POST'])
def logout(uid):
    #do session management, remove current user from curret logged llist, remove session id
    return redirect('/')

@app.route('/revokeCert/<string:uid>$<string:serialN>', methods=['POST'])
def revokeCert(uid, serialN):
    try:
        response = requests.put(url +"/revoked", json={'uid':uid, "serialnumber":serialN}).json()
        if(response["Success"]==1):
            return redirect('/user/'+uid)
        else:
            return "revokation unsuccessful"
    except:
        return "failed to connect to db"


if __name__ == "__main__":

    #populate db before running

    app.run(debug=True)
