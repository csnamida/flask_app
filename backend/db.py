from flask_sqlalchemy import SQLAlchemy
from .config import app

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()