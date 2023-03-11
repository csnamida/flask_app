from flask_sqlalchemy import SQLAlchemy
from .config import app

db = SQLAlchemy(app)
