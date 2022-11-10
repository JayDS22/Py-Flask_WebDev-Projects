#----> {DISTRIBUTED Scripts}
# 
# 
# AIM: Create A [] TODO-List [] FLASK - Application

#* Logics To be Implemented
#--------------------------
#- Overview
    #- Create a RESTful API, on Flask, with 2 major components. API has 
    #      1. List of Users
    #      2. List of TODO Components
    
    #- Users' related Routes & Methods
    #      1. Create a Users Class DB in SQLite with 5 attributes (Include , "Admin" as a Boolean )
    #          - Admin will have Additional access to the website
    #      2. Involve a "Public-Id", that can be visible in the Token's header | Created using UUID | To protect the Real ID
    #      3. Create Methods to { "Create_New_User" || "Promote_User" || "Delete_User" || "Get_List_of_All_Users" || "Get_One_User"}

    #- Todo related Routes & Methods
    #      1. Create a TODO Class DB in SQLite with 4 attributes (Include "Complete" as Bool)
    #         - "Complete" will track the status of the TO-DO task
    #      2. Involve a "user_id" (same as "id" from User class)
    #      3. Create Methods to {"Create_Todo" || "Get_All_Todo" || "Get_One_Todo" || "Complete_Todo" || "Delete_Todo"}
    #         - Initial TODO created , keep [ "complete = False" /\ "user_id" = "current_user's ID"
    #         - TODO's should be Checked w.r.t. "USER_ID" = "CURRENT_USER' id" && "Todo_Id" = "Todo_Id"
    #- Embed JWT authentication, required to login to the application
    #- DETAILED UNDERSTANDING of { JWT - Token Authorization }

    #      1. Create "Login" Route & Method
    #           - Create 3 Authentication Layers
        #           - 1st Layer: w.r.t. Username & Password authentication (optional) 
        #               - If not, Return "Error" JSON , 401
        #           - 2nd Layer: w.r.t. USER table's data 
        #               - If not, Return "Error" JSON , 401
        #           - 3rd Layer: w.r.t.  User table's data && "Hashed_Password"
        #               - If All 3 layers passed
        #                    - Create JWT Token (encode the Payload, expiration Time) || w.r.t. SECRET_KEY
        #                    - Return Json O/P (JWT token decoded, using UTF-8 
    #           - Return Response "Error" || Acting as "Else statement" for all above layers

    #      2. Protect List Of Users, using JWT Token Authentication
    #           - Using that Token, will PUT IN a "Header" for subsequent requests
    #           - Make Sure JWT Authentication has Expiration time as a "UTC" Time Stamp

    #      3. Create a DECORATOR "token_required" to generate Tokens & Secure other Routes
    #           - Decorator Takes in "Arguments" & "Keyword Args" -> Create a WRAP Function.
        #           - Initializes the Token = None 
        #           - Captures only JWT's "Header"
        #           - Perfoms Token Verification & Decodes the Token in 2 Steps
        #           - Extract "CURRENT_USER" related details from the "User" table w.r.t. "Unique_Key"
    #           - Returns "Current_User" + "Token" (in form of args)

    #      4. Add {} @token_required {} decorator to "Protect" desired Routes.
    #           - Add Below Functionalities in ALL the Routes
        #           - "JWT Token" should be generated individually for "CURRENT_USER"
        #           - "CURRENT_USER" should be added as "mandatory attribute"  -> In "All METHODS"
        #             - Give Condition in "All_Methods" for "USER"
        #                    - Only Access to "CURRENT_USER", if ADMIN

        #             - Give Condition in "All_Methods" for "TODO"
        #                    - All USERS will have Access to


    

#- Imports
import datetime
import os
import uuid
from boto import config #To create Secret_Key & Public_Id
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash 
from models import User, Todo
from jwt_main import token_required
import config


# Create Flask App
app = Flask(__name__)

# Set Up Base Directory (To avoid any errors)
basedir = os.path.abspath(os.path.dirname(__file__))

#- Configure App & DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir, 'todo.db')

#- Initiate DB w.r.t. App
db = SQLAlchemy(app)


######################## Structure Routes #####################

#- Get_All_Users
@app.route('/user', methods=['GET'])
@token_required #Adding "Token" Decorator, to add the functionality & Protection to the relevant routes
def get_all_users(current_user):
    
    # Adding a Check to Verify if current user = ADMIN
    if not current_user.admin:
        return jsonify({'message' : 'This Function cannot be performed !'})

    # Query the User Table, as per ORM (SQLAlchemy)
    users = User.query.all()

    output = []
    
    #- For Loop iterates to Each Users' details & return User Data in LIST that has JSON format
    for user in users:

        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

#- Get_One_User
@app.route('/user', methods=['GET'])
@token_required
def get_one_user(current_user ,public_id): #Input Attribute "public_id"
    # Adding a Check to Verify if current user = ADMIN
    if not current_user.admin:
        return jsonify({'message' : 'This Function cannot be performed !'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No User found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

#- Create User
@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    # Adding a Check to Verify if current user = ADMIN
    if not current_user.admin:
        return jsonify({'message' : 'This Function cannot be performed !'})

    # Get name & password as input data in Json form
    data = request.get_json()
    # Hash the original password
    hashed_password = generate_password_hash(data['password'], method='sha256')
    # Initially the User added will not be Admin | can be promoted thou.
    new_user = User(public_id = str(uuid.uuid4()), name = data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New User Created!'})

#- Promote User || To Change Status of User w.r.t. "Admin"
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user ,public_id):
    # Adding a Check to Verify if current user = ADMIN
    if not current_user.admin:
        return jsonify({'message' : 'This Function cannot be performed !'})

    #- Initially Check if the User is available
    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    # Works like a Else statement
    user.admin =True
    db.session.commit()

    return jsonify({'message' : 'User has been promoted'})

#- Delete User
@app.route('/user/<public_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, public_id):
    # Adding a Check to Verify if current user = ADMIN
    if not current_user.admin:
        return jsonify({'message' : 'This Function cannot be performed !'})

    # User exist check
    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'The User has been deleted'})

######################## JWT Authentication Login Method ########################

#-- ONLY the Login Route works with "http://" authentication, Other Routes will be Secured with Token
@app.route('/login', methods=['POST', 'GET'])
def login():
    auth = request.authorization
    # 1st Authentication Layer
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-AUTHENTICATE': 'Basic realm = "Login required!"'})
    
    # 2nd Authentication Layer
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-AUTHENTICATE' : 'Basic realm = "Login required!"'})
    
    # If Above 2 Works, Check 3rd Layer "Password_Hash" || If That works || Create JWT
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, config.BaseConfig.SECRET_KEY)
        return jsonify({'token' : token.decode('UTF-8')})
    
    # If All above Checks Fail, we Give Error Response
    # Alternative Idea: If we have a Robust Login Page's UI, we can redirect_url back to login page
    return make_response('Could not verify', 401, {'WWW-AUTHENTICATE' : 'Basic realm = "Login required!"'})

#--- Code Run Note: While Checking the "Login" route 
#--- (In Postman) Use "Authoraization" -> select "Basic Auth" -> Give "Username" & "Password" avlb. in "User" table aleady

######################## TODO Methods Routes ######################

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    # Extract TODO w.r.t. Current - User
    todos = Todo.query.all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos' : output})

@app.route('/todo/<todo_id>', methods = ['GET'])
@token_required
def get_one_todo(current_user ,todo_id):

    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo item found'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    return jsonify({'todo' : todo_data})

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Todo(text = data['text'], complete = False, user_id = current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : 'New todo created!' })

@app.route('/todo/<todo_id>', methods = ['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    
    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'Todo not found!'})
    
    todo.complete = True
    db.session.commit()
    return jsonify({'message' : 'Todo is completed!'})


@app.route('/todo/<todo_id>', methods = ['DELETE'])
@token_required
def delete_todo(current_user, todo_id):

    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})
    
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message' : 'Todo is deleted!'})

######################## Main Run ######################## 
if __name__ == '__main__':
    # with app.app_context():
    #    db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)


#--> Test Run (with JWT Implementation)

#* NOTE: Add "x-access-token" : token || in Postman in "headers" always, for all protected routes
#*







