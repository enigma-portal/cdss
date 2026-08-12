from flask import Flask
from app.database import initialize_database

app = Flask(__name__)

# Make sure the local SQLite database is ready whenever the app starts.
initialize_database()


@app.route("/")
def home():
    return "Cyber Decision Support System is running!"


if __name__ == "__main__":
    app.run(debug=True)
