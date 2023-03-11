from .config import app, ACCESS_EXPIRES, jwt_redis_block_list
from flask import json
from flask_restful import Resource, Api, reqparse
from .models import UserModel, db
from sqlalchemy import select
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, get_jwt

api = Api(app)

user_parser = reqparse.RequestParser()
user_parser.add_argument('username', type=str, help='Username is required.', required=True)
user_parser.add_argument('password', type=str, help='Password is required.', required=True)


class Register(Resource):
    def post(self):
        args = user_parser.parse_args()
        username, password = args['username'], args['password']
        user = find_user(username)

        if user is None:
            new_user = UserModel(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
        
            return app.response_class(
                status=200,
                response=json.dumps({"msg": "Account successfully registered."}),
                mimetype='application/json'
            )

        return app.response_class(
            status=400, 
            response=json.dumps({"msg": "User already exists."}), 
            mimetype='application/json'
        )
    

class User(Resource):
    @jwt_required()
    def put(self, username):
        args = user_parser.parse_args()
        user = find_user(username)
        user[0].password = generate_password_hash(args['password'])

        db.session.commit()

        return app.response_class(
            status=200,
            response=json.dumps({"msg": "Password was successfully updated."}),
            mimetype='application/json'
        )
    

class Login(Resource):
    def post(self):
        args = user_parser.parse_args()
        user = find_user(args['username'])

        if user is not None and user[0].check_password(args['password']):
            access_token = create_access_token(identity=args['username'])
            user[0].is_authenticated = True
            db.session.commit()

            return app.response_class(
                status=200,
                response=json.dumps({
                    "msg": "Login successfully",
                    "access_token": access_token
                }),
                mimetype='application/json'
            )
            

        return app.response_class(
            status=404,
            response=json.dumps({"msg": "Invalid username or password."}),
            mimetype='application/json'
        )
        
class Logout(Resource):
    @jwt_required()
    def post(self):
        user = find_user(get_jwt_identity())
        user[0].is_authenticated = False
        db.session.commit()
        jti = get_jwt()["jti"]
        jwt_redis_block_list.set(jti, "", ex=ACCESS_EXPIRES)
        
        return app.response_class(
            status=200,
            response=json.dumps({"msg": "You have been logout."}),
            mimetype='application/json'
        )
        
def find_user(username):
    return db.session.execute(select(UserModel).where(UserModel.username==username)).first()
    

api.add_resource(Register, '/register')
api.add_resource(User, '/user/<username>')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')