from .db import db
from sqlalchemy.orm import relationship, backref

class UserModel(db.Model):
    __tablename__ = "user_account"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __repr__(self) -> str:
        return f"Username: {self.username}"

class TaskModel(db.Model):
    __tablename__ = "user_task"
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    user_id = db.Column(db.ForeignKey(UserModel.id))
    user = relationship(UserModel, backref=backref("usermodel", cascade="all,delete"))
