from .config import app 
from flask_restful import Resource, Api, reqparse
from .models import UserModel, db
from sqlalchemy import select
from werkzeug.security import generate_password_hash

api = Api(app)

class User(Resource):
    user_parser = reqparse.RequestParser()
    user_parser.add_argument('username', type=str, help='Username is required.', required=True)
    user_parser.add_argument('password', type=str, help='Password is required.', required=True)

    def post(self):
        args = self.user_parser.parse_args()
        username, password = args['username'], args['password']
        user = find_user(username)

        if user is None:
            new_user = UserModel(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
        
            return {"message": "User was successfully created."}, 201

        return {"message": "Username already exists."}, 400

def find_user(username):
    return db.session.execute(select(UserModel).where(UserModel.username==username)).first()
    

api.add_resource(User, '/user')