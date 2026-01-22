"""Flask application with intentional good and bad code examples for AI PR review testing."""
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session
from routes.user_routes import user_bp

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Initialize database
db = SQLAlchemy(app)

# Register blueprints
app.register_blueprint(user_bp)


# GOOD PRACTICE: Dependency injection for database session
@app.before_request
def before_request():
    """GOOD PRACTICE: Make database session available via Flask g."""
    g.db = db.session


# GOOD PRACTICE: Cleanup after request
@app.teardown_appcontext
def teardown_db(exception):
    """GOOD PRACTICE: Proper session cleanup."""
    db.session.remove()


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/health')
def health_check():
    """GOOD PRACTICE: Health check endpoint."""
    return {'status': 'healthy'}, 200


if __name__ == '__main__':
    # Create tables (in production, use migrations)
    with app.app_context():
        # Import models to register them
        from models.user import User
        # Create all tables
        db.create_all()
    
    app.run(debug=True)
