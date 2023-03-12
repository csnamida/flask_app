from flask import Flask
from datetime import timedelta
from flask_jwt_extended import JWTManager
import redis

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
app.config["SECRET_KEY"] = "d73d59f2-a943-44a4-b1fc-fe8b3e909f36"
app.config["JWT_SECRET_KEY"] = "fa90c298-52e1-462b-953a-8a34dcd8c430"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False

jwt = JWTManager(app)
jwt_redis_block_list = redis.StrictRedis(
    host='localhost',
    port=6379,
    db=0,
    decode_responses=True
)


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload['jti']
    token_in_redis = jwt_redis_block_list.get(jti)

    return token_in_redis is not None
