from .config import app
from flask_restful import Resource, Api

api = Api(app)

class User(Resource):
    def get(self):
        return {"Name": "Christian"}

api.add_resource(User, '/user')