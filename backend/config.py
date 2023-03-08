from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "d73d59f2-a943-44a4-b1fc-fe8b3e909f36"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"