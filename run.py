from flask import Flask
from app.database import initialize_database
from config import PROJECT_TITLE

app = Flask(__name__)

# Make sure the local SQLite database is ready whenever the app starts.
initialize_database()


@app.route("/")
def home():
    return f"{PROJECT_TITLE} is running!"


if __name__ == "__main__":
    app.run(debug=True)
