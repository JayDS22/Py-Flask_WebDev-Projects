#>>>> AIM: To authenticate Flask API using JWT (Basics) <<<<#

#* For Demo:
#-----------
#+ [Logic-1]: To Create Multiple Routes, for Protected & Unprotected Content, that requires JWT Tokens,
#           to Login & refer the content.
#  - Route-1 : Unprotected || Can be accessed by anyone
#  - Route-2 : Protected || Can be accessed by Users only with JWT web tokens
#  - Route-3: Login || To authenticate the Users' based on Certain Login Inputs & Gives Token, if valid

#+ [Logic-2]: Multiple Routes Can be Made SECURE, if "Token_Required" for those specific routes is made,
#           Compulsory. 

# || DECORATOR To Validate Tokens, for URL requests & Protect Multiple Routes

#           - Decorator using WRAPS function, can be taken into considerations.
#           - Decorator will take "Keyword" args and check if the token & requests are Valid.
#              -- If Valid: Let User continue on the similar route /\ If InValid: Give Error Message 'Token is Invalid'
#           - {Users of API can pass Tokens OR App can GET token},  to  APP in Multiple ways, the easiest is "Query-String"
#              -- "Query String" : Writing Token in URL of the API
#           - Adding, "If Nothing for token" cond, return msg | "If token given then decode" refer SECRET KEY | "If token is invalid" cond, return msg

# || Conclusion: Need to Go to "LOGIN" -> Generate Token  ->  Use it In "Query String" to {View "Protected Routes"}
#-----------

# Error Handling References:
#https://stackoverflow.com/questions/67333286/flask-failing-to-verify-jwt-signature-for-protected-routes

#-----------
#Imports
from datetime import datetime
from textwrap import wrap
from flask import Flask, request, jsonify, make_response
import jwt
import datetime
from functools import wraps #Takes in random keyword arguments, and used to validate the tokens


#Initialize Web-App
app = Flask(__name__)
app.config['SECRET_KEY'] = '498a92bcd4734c23b1f3e22d59b977bd'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') #https://127.0.0.1:5000/route?token=vwhdchvchmcsdjhvfvewfwi

# If we don't have a Token for Protected Routes, "Decorator" won't let us Pass the 'Token is missing' Error
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            #current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs) #This Returns the Key Word Arguments, based on Key words inputed w.r.t. the fuction
    return decorated #Returning this function so that the Outer function Knows what to do

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'This page can be accessed by anyone'})

@app.route('/protected')
@token_required #Adding This route to be protected with Token
def protected():
    return jsonify({'message' : 'Only Authenticated Users can access this page'})

@app.route('/qbrReports')
@token_required #Adding this route to be protected with Token
def qbr_reports():
    return jsonify({
        'message' : 'Welcome to QBR Reports',
        'Customer Name' : 'Area Wide Protective',
        'ID' : 1111,
        'No. of Drivers' : 3456,
        'Avg. Miles Travelled per 100 Miles' : 67.19,
        'Top Ranking Drivers' : ['Jay', 'Sharath', 'Chandan', 'Soukhinder', 'Pitul', 'Sakshi', 'Erwin']})

@app.route('/login')
def login():
    auth = request.authorization #To request User Name & Password Authorization

    if auth and auth.password == '123456':
        token = jwt.encode({'user':auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'] )
        return jsonify({'token' : token})
        #return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify!',401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

#Define Routes for Web App
if __name__ == '__main__':
    app.run(debug=True)


