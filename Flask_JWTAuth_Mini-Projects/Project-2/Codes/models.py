
from app import db

####################### Define User & Todo Class ####################### 

class User(db.Model):

    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

    def __init__(self, id, public_id, name, password, admin):
        self.id = id
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin

    def __repr__(self):
        return f'Name : {self.name}, Public_Id : {self.public_id}'

class Todo(db.Model):

    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    user_id = db.column(db.Integer)

    def __init__(self, id, text, complete, user_id):
        self.id = id
        self.text = text
        self.complete = complete
        self.user_id = user_id

    def __repr__(self):
        return f'Name : {self.id}, Public_Id : {self.text}'

#--- Run Code till here, To Create the DataBase (todo.db, with 2 tables)
#--- To Check if Table Exists -> go to Terminal -> type "sqlite3 db.name" -> type ".tables"
