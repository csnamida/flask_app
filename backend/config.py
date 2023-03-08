from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "f0255b0b-2fed-461f-94ac-401cac988327"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"