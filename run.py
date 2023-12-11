# Import necessary libraries and modules
from flask import Flask, render_template, redirect, url_for, request, session
from dotenv import load_dotenv
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
import bcrypt

# Load environment variables from the .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
# Set a secret key for session management
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
# Configure SQLite database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# Initialize SQLAlchemy for database management
db = SQLAlchemy(app)

# RSA key pair generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Save the private key securely
with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Share the public key with others
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Encryption/decryption key setup
key = os.getenv('ENCRYPTION_KEY')
if key is None:
    raise EnvironmentError("Encryption key not found in environment variables.")

# RSA public key loading
with open('public_key.pem', 'rb') as f:
    rsa_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Encrypt the Fernet key using RSA public key
encrypted_key = rsa_public_key.encrypt(
    key.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
encrypted_key_hex = encrypted_key.hex()

# Create a Fernet cipher suite using the Fernet key
cipher_suite = Fernet(key)

# Define User and Customer database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

# Use app context to create tables
with app.app_context():
    db.create_all()

# Define Flask routes
@app.route('/')
def home():
    # Redirect to the login page
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve username and password from the login form
        username = request.form['username']
        password = request.form['password']

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is correct
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            # Store the user in the session and redirect to the dashboard
            session['user'] = username
            return redirect(url_for('dashboard'))

    # Render the login template
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve username and password from the signup form
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            # Render the signup template with an error message
            error_message = "Username already exists. Please choose another one."
            return render_template('signup.html', error_message=error_message)

        # Check if the password meets the length requirement
        if len(password) < 8:
            # Render the signup template with an error message
            error_message = "Password must be at least 8 characters long."
            return render_template('signup.html', error_message=error_message)

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Create a new user and add it to the database
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the login page after successful signup
        return redirect(url_for('login'))

    # Render the signup template
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    # Check if the user is authenticated
    authenticated_user = session.get('user')
    if authenticated_user:
        # Query all customers from the database
        customers = Customer.query.all()
        # Decrypt customer data for display in the dashboard
        decrypted_data = [
            {
                'name': cipher_suite.decrypt(customer.name.encode('utf-8')).decode('utf-8'),
                'email': cipher_suite.decrypt(customer.email.encode('utf-8')).decode('utf-8'),
                'phone': cipher_suite.decrypt(customer.phone.encode('utf-8')).decode('utf-8')
            }
            for customer in customers
        ]
        # Render the dashboard template with user information and decrypted data
        return render_template('dashboard.html', user=authenticated_user, data=decrypted_data)
    else:
        # Redirect to the login page if the user is not authenticated
        return redirect(url_for('login'))

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    # Check if the user is authenticated
    authenticated_user = session.get('user')
    if authenticated_user:
        # Retrieve customer information from the form
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']

        # Encrypt customer information using the Fernet cipher suite
        encrypted_name = cipher_suite.encrypt(name.encode('utf-8')).decode('utf-8')
        encrypted_email = cipher_suite.encrypt(email.encode('utf-8')).decode('utf-8')
        encrypted_phone = cipher_suite.encrypt(phone.encode('utf-8')).decode('utf-8')

        # Create a new customer and add it to the database
        new_customer = Customer(name=encrypted_name, email=encrypted_email, phone=encrypted_phone)
        db.session.add(new_customer)
        db.session.commit()

        # Redirect to the dashboard after successfully adding a customer
        return redirect(url_for('dashboard'))

    # Redirect to the login page if the user is not authenticated
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Run the application in debug mode with SSL/TLS support for development
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
