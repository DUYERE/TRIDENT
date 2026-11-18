from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.route("/home")
@login_required
def home():
    return "ok"
