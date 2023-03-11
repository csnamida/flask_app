from .db import db
from .config import app
from sqlalchemy.orm import relationship, backref
from werkzeug.security import check_password_hash

class UserModel(db.Model):
    __tablename__ = "user_account"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    is_authenticated = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f"Username: {self.username}"
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

class TaskModel(db.Model):
    __tablename__ = "user_task"
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    user_id = db.Column(db.ForeignKey(UserModel.id))
    user = relationship(UserModel, backref=backref("usermodel", cascade="all,delete"))


# with app.app_context():
#     db.create_all()