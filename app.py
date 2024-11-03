from flask import Flask, render_template, redirect, url_for, flash, request, session, app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from pymongo import MongoClient
from datetime import timedelta
from flask_mail import Mail, Message

from flask import Flask, render_template, request, url_for, redirect, session
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=5)  # Set session lifetime to 5 minutes


app.config['MAIL_SERVER']='live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'api'
app.config['MAIL_PASSWORD'] = 'b5f70d2eb72ccf4d56ae93d52165bff9'
app.config['MAIL_DEFAULT_SENDER'] = 'thisIsAbdullah@demomailtrap.com'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

uri = "mongodb+srv://abdo:eIjs3QqGNVs6f2DB@db-flask-app.t6gyb.mongodb.net/?retryWrites=true&w=majority&appName=db-flask-app"
client = MongoClient(uri)

 
#encryption relies on secret keys so they could be run
app.secret_key = "testing"

# #connect to your Mongo DB database
def MongoDB():
    client = MongoClient("mongodb+srv://abdo:eIjs3QqGNVs6f2DB@db-flask-app.t6gyb.mongodb.net/?retryWrites=true&w=majority&appName=db-flask-app")
    database = client.get_database("users_db")
    records = database.register
        
    return records
records = MongoDB()

#assign URLs to have a particular route 
@app.route("/register", methods=['post', 'get'])
def index():
    message = 'Please Register!'
    #if method post in index
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password': password2}
            #insert it in the record collection
            records.insert_one(user_input)
            
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            return render_template('logged_in.html', email=new_email)
    return render_template('index.html', message=message)

@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #check if email exists in database
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            name_ret = email_found['name']
            passwordcheck = email_found['password']
            #encode the password and check if it matches
            if passwordcheck: #bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                session["name"] = name_ret
                # #After Verify the validity of username and password
                session.permanent = True    
                return redirect(url_for("logged_in"))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        name = session["name"]
        #After Verify the validity of username and password
        session.permanent = True   
        return render_template('logged_in.html', email=email, name=name)
    else:
        return redirect(url_for("login"))

@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        session.pop("name", None)
        return render_template("signout.html")
    else:
        # return render_template('login.html')
        return redirect(url_for('login'))
    
@app.route("/forgot_password", methods=['POST','GET'])
def forgot_password():
    message='Please enter your email'
    if request.method == 'POST':
        ffffffffffemail = request.form.get('forgot_pass_email')
        forgot_pass_email = records.find_one({"email": ffffffffffemail})
      
        if forgot_pass_email:
            user_forgotpass_name = forgot_pass_email['name']
            user_forgotpass_email = forgot_pass_email['email']
            user_forgotpass = forgot_pass_email['password']
            # if bcrypt.checkpw(user_forgotpass.decode('utf-8'), user_forgotpass):
            session["user_forgotpass_name"] = user_forgotpass_name
            session["forgot_pass_email"] = user_forgotpass_email
            session["user_forgotpass"] = user_forgotpass
            
            send_email(user_forgotpass_name, user_forgotpass_email, user_forgotpass)
            
            message = 'Please check your email the password has been sent to your email'
            return render_template('forgot_password.html', message=message)
        else:
            flash('Email not found.', 'danger')
    
    return render_template('forgot_password.html', message=message)

def send_email(name, email, password):
    msg = Message( 
        subject = 'Forgot password!', 
        sender ='ThisIsAbdullah@demomailtrap.com', 
        recipients = ['abdullahesmatullah@gmail.com'] 
        ) 
    msg.body = f'Your name is {name}, your email is {email}, and your password is {password}'
    # msg.body = 'your password is'
    mail.send(msg)
    return 

# app.route("/forgot_password_page")
# def forgot_password_page():
#     if ""
    
    
@app.before_request
def make_session_permanent():
    session.permanent = True  # Make the session permanent on each request

if __name__ == "__main__":
  app.run(debug=True, host='0.0.0.0', port=5000)
