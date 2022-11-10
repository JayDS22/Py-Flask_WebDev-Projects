#---> IMPORTS
#- "render_template" lib is used to create a Login Form, using HTML, and integrate that with Python
#- "request" lib helps us posting, getting performing etc methods to Request the server & generate "Tokens"
from flask import Flask, request, jsonify, make_response, render_template, session, flash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '7526626e38014d0884fce5cb7258cd99'

#3. Create a "Token Function" || To generate & validate JWT
# Create a Decorator, that allows you to add new functionality in existing function
# Logic: Function "wraps" invokes a function "update_Wrapper"
#        Create a Nested function, that takes "arguments" & "key-word arguments" | This fuction is invoked by "wraps"
#          Nested func, used to build a TOKEN, & if not "Token", return JSON Key: value message
#          Nested func, gives O/P as "Payload" data, that configures 'SECRET_KEY'

def token_required(func):
    @wraps(func)
    def decorated(args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!':'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        # You can use the JWT errors in exception
        # except jwt.InvalidTokenError:
        # return 'Invalid token. Please log in again.'
        except:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)
    return decorated

#1. Create First Route
#- For Initial URL Path
# Logic:  To say, If I am not logged in, reroute the app page to "Login",
#         Else say "Logged in Currently

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Logged in currently!'

#4. Create Route
#- For Secondary URL path ("/public")
#- Logic: Create a URL that is Publically available, w/o any authentication
@app.route('/public')
def public():
    return'For Public'

#5. Create Route
#- For Secondary URL path ("/auth")
#- Logic: Create a URL that is Only for Authenticated Users
#         For this Route "Token_Required" function = Mandatory
@app.route('/auth')
@token_required
def auth():
    return ' JWT is verified. Welcome to your dashboard! '

#2. Create Route
#- For Secondary URL Path ("/login")
#- Logic: To Enter Name & Password in HTML page -> If Verified -> gives "Token",
#         Making sure user Logging through JWT, not cookie/session
#         Adding Time Expiration of Token for security purposes, upto 2 minutes
#         Add "SECRET_KEY" Needed To Read signature of JWT Token
#         Decode the Token in JSON form

@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '12345':
       session['logged_in'] = True
       token = jwt.encode({
          'user': request.form['username'],
          'expiration': str(datetime.utcnow() + timedelta(seconds=120))
       },
       app.config['SECRET_KEY']) #Needed To Read signature of JWT Token
       return jsonify({'token': token.encode().decode('utf-8')})
    else:
      return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed!'})


#6. Create a Route
#- Logic: Secondary Route, to Log-Out
@app.route('/logout', methods=['POST'])
def logout():
    pass
# your code goes here


#---> Main Code to Call the File
if __name__== "__main__":
    app.run(debug=True)