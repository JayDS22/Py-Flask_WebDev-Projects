
import jwt
from flask import jsonify, request, make_response
from models import User
from functools import wraps
import config




######################## Decorator for JWT Token ###################

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        #- Initiate NONE token
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
         
        #- Try-Except Block used (As we are decoding & checkin)
        try: 
            data = jwt.decode(token, config.BaseConfig.SECRET_KEY)

            #- To Capture the User, Who Using this application currently.
            #- Current_User should be added as Attribute to All Methods with Functionality
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        #- Once we Pass All the Authentications w.r.t. JWT token -> Return "Token" Key words args w.r.t. a "User"
        #- Need to Pass the USER w.r.t. the "Routes"
        return f(current_user, *args, **kwargs)
    return decorated
