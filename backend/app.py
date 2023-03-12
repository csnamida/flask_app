from .config import app, ACCESS_EXPIRES, jwt_redis_block_list, jwt
from flask import json, jsonify
from flask_restful import Resource, Api, reqparse
from .models import UserModel, TaskModel, db
from sqlalchemy import select
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, current_user, set_access_cookies, unset_jwt_cookies
from datetime import datetime, timezone, timedelta

api = Api(app)

user_parser = reqparse.RequestParser()
user_parser.add_argument('username', type=str,
                         help='Username is required.', required=True)
user_parser.add_argument('password', type=str,
                         help='Password is required.', required=True)

task_parser = reqparse.RequestParser()
task_parser.add_argument(
    'title', type=str, help='Title is required.', required=True)


class Register(Resource):
    """
    API used to register user
    """

    def post(self):
        args = user_parser.parse_args()
        username, password = args['username'], args['password']
        user = Utils.find_user(username)

        if user is None:
            new_user = UserModel(
                username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()

            return {"msg": "Credentials successfully registered."}, 201

        return {"msg": "User already exists."}, 400


class User(Resource):
    @jwt_required()
    def put(self, username):
        args = user_parser.parse_args()
        user = Utils.find_user(username)
        user[0].password = generate_password_hash(args['password'])

        db.session.commit()

        return {"msg": "Password was successfully updated."}, 200


class Login(Resource):
    def post(self):
        args = user_parser.parse_args()
        user = Utils.find_user(args['username'])

        if user is not None and user[0].check_password(args['password']):
            access_token = create_access_token(identity=user[0])
            user[0].is_authenticated = True
            db.session.commit()
            response = jsonify({"msg": "Login successfully."})
            set_access_cookies(response, access_token)

            return response

        return {"msg": "Invalid username or password."}, 401


class Logout(Resource):
    @jwt_required()
    def post(self):
        current_user.is_authenticated = False
        db.session.commit()
        jti = get_jwt()["jti"]
        jwt_redis_block_list.set(jti, "", ex=ACCESS_EXPIRES)
        response = jsonify({"msg": "You have been logout."})
        unset_jwt_cookies(response)
        return response


class Task(Resource):

    @jwt_required()
    def post(self):
        args = task_parser.parse_args()
        task = Utils.find_task_using_title(args['title'])

        if task is not None:
            return {"msg": "Task already exists."}, 400

        new_task = TaskModel(
            title=args['title'], user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()

        return {"msg": "Task was successfully added."}, 200

    @jwt_required()
    def get(self):
        tasks = db.session.execute(
            select(TaskModel).where(TaskModel.user_id == current_user.id)).all()

        if tasks is None:
            return {"msg": "There are no current available todo task."}, 404

        todo_tasks = [{task[0].id: task[0].title} for task in tasks]

        return todo_tasks, 200


class UserTask(Resource):
    @jwt_required()
    def put(self, id):
        task = Utils.find_task_using_id(id)

        if task is None:
            return {"msg": "Task not found."}, 404

        args = task_parser.parse_args()

        if task[0].title.lower() == args['title'].lower():
            return {"msg": "Use different title."}, 400

        task[0].title = args['title']
        db.session.commit()

        return {"msg": "Task successfully updated."}, 200

    @jwt_required()
    def delete(self, id):
        task = Utils.find_task_using_id(id)

        if task is None:
            return {"msg": "Task not found."}, 404

        db.session.delete(task[0])
        db.session.commit()

        return 204


class Utils:
    @staticmethod
    def find_user(username):
        return db.session.execute(select(UserModel).where(UserModel.username == username)).first()

    @staticmethod
    def find_task_using_title(title):
        return db.session.execute(select(TaskModel).where(TaskModel.title == title)).first()

    @staticmethod
    def find_task_using_id(id):
        return db.session.execute(select(TaskModel).where(TaskModel.id == id)).first()


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return user[0] if (user := db.session.execute(select(UserModel).where(UserModel.id == identity)).first()) else None


@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=current_user)
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        return response


api.add_resource(Register, '/register')
api.add_resource(User, '/<username>')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Task, '/tasks')
api.add_resource(UserTask, '/task/<id>')
