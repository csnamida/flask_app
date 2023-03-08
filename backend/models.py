from .db import db
from .config import app
from datetime import datetime
from sqlalchemy.orm import relationship

class UserModel(db.Model):
    __tablename__ = "user_account"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    nickname = db.Column(db.String)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    task = relationship("TaskModel", cascade="all,delete", backref="usermodel")

    def __repr__(self) -> str:
        return self.username

class TaskModel(db.Model):
    __tablename__ = "user_tasks"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey(UserModel.id), nullable=False)
    title = db.Column(db.String, unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return self.title

with app.app_context():
    db.create_all()