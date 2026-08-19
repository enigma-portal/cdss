from flask import Flask
from app.database import initialize_database
from app.database.seed import seed_knowledge_base
from app.routes.dashboard import dashboard
from config import PROJECT_TITLE

app = Flask(__name__)
app.config["PROJECT_TITLE"] = PROJECT_TITLE
app.register_blueprint(dashboard)

# Make sure the local SQLite database is ready whenever the app starts.
initialize_database()
seed_knowledge_base()

if __name__ == "__main__":
    app.run(debug=True)
