from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os, pickle
from Blockchain import Blockchain

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_super_secret_key'

# SQLite DB config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

blockchain_path = 'blockchain_contract.txt'
blockchain = Blockchain()
if os.path.exists(blockchain_path):
    with open(blockchain_path, 'rb') as f:
        blockchain = pickle.load(f)
else:
    blockchain = Blockchain()  # Create a new blockchain if none exists


@app.route('/')
def home():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/save_certificate', methods=['POST'])
def save_certificate():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        form = request.form
        file = request.files.get('certificate_file')
        if not all([form.get('matric_no'), form.get('student_name'), form.get('department'), form.get('issuer'), file]):
            return "Missing input fields.", 400

        os.makedirs("saved_certificates", exist_ok=True)
        filepath = os.path.join("saved_certificates", file.filename)
        file.save(filepath)
        file.seek(0)

        from hashlib import sha256
        import datetime
        file_hash = sha256(file.read()).hexdigest()

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        transaction = {
            'Matric_no': form['matric_no'],
            'name': form['student_name'],
            'Department': form['department'],
            'issuer': form['issuer'],
            'digital_signature': file_hash,
            'file_path': filepath,
            'timestamp': timestamp
        }

        blockchain.add_new_transaction(transaction)
        mine_result = blockchain.mine()
        with open(blockchain_path, 'wb') as f:
            pickle.dump(blockchain, f)

        # Get full block info
        last_block = blockchain.last_block
        block_number = last_block.index

        # Log to a file
        with open("blockchain_log.txt", "a") as log:
            log.write(f"[{timestamp}] Block #{block_number} mined. Hash: {file_hash}\n")

        result = (
            f"✅ Certificate saved and signed.\n"
            f"Block Number: {block_number}\n"
            f"Timestamp: {timestamp}\n"
            f"Digital Signature (Hash): {file_hash}\n"
            f"Block Info:\n{last_block}"
        )
        return result
    except Exception as e:
        return f"Error saving certificate: {e}", 500
    

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    try:
        file = request.files.get('certificate_file')
        if not file:
            return "No file provided.", 400

        from hashlib import sha256
        import datetime
        file_hash = sha256(file.read()).hexdigest()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for block in blockchain.chain:
            for tx in block.transactions:
                if tx.get("digital_signature") == file_hash:
                    match_info = (
                        f"✅ Certificate is valid and verified.\n"
                        f"Verification Time: {timestamp}\n"
                        f"Block Number: {block.index}\n"
                        f"Block Timestamp: {block.timestamp}\n"
                        f"Block Info: {block}\n"
                        f"Matched Certificate Details:\n"
                        f"Matric No: {tx['Matric_no']}\n"
                        f"Student Name: {tx['name']}\n"
                        f"Department: {tx['Department']}\n"
                        f"Issuer: {tx['issuer']}\n"
                        f"Certificate Timestamp: {tx.get('timestamp', 'N/A')}"
                    )
                    return match_info

        return "❌ Certificate not found or tampered."
    except Exception as e:
        return f"Error verifying certificate: {e}", 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
