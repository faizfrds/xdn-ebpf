from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    with open("test.txt", "w") as fo:
        fo.write("hello_world")
    return "<p>Hello, World!</p>"

