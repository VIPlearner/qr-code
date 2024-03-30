from hashlib import sha256
from os import environ
from time import sleep

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, current_user
from flask_mail import Mail, Message
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.config import SECRET_KEY, SECURITY_PASSWORD_SALT, QR_ITEMS_PER_PAGE
from src.models.QRInfo import QRInfo
from src.models.UserAuth import UserAuth
from src.security_utils import confirm_token, send_verification_mail, send_password_verification_mail
from src.utils import check_strong_password, init_db

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET')
jwt = JWTManager(app)

app.config['POSTGRES_DB_URI'] = environ.get('POSTGRES_DB_URI')
app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = environ.get('SECURITY_PASSWORD_SALT')
app.config['MAIL_SERVER'] = environ.get('EMAIL_SERVER')
app.config['MAIL_PORT'] = environ.get('EMAIL_PORT')
app.config['MAIL_USERNAME'] = environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = environ.get('EMAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)
mail.connect()

# db setup
engine = create_engine(app.config['POSTGRES_DB_URI'])
Session = sessionmaker(bind=engine)
db_session = Session()

session = Session()

init_db(engine, session)


@app.route('/')
def hello_world():  # put application's code here
    msg = Message('Hello', sender='joshuaoluwasegun99@gmail.com', recipients=['joshuaoluwasegun99@gmail.com'])
    msg.body = "This is the email body"
    print('Sending email')
    mail.send(msg)
    return "Sent"


@app.route('/resource', methods=['GET'])
@jwt_required()
def get_resource():
    # Replace this with the actual logic to get the resource
    print(f"current user {current_user}")
    auths = db_session.query(UserAuth).all()
    return f"auths: {auths}"


@app.route('/login', methods=['POST'])
def login():
    sleep(2)  # artificial latency to prevent timing attacks
    username = request.json['username'].lower()
    password = request.json['password']
    password_hash = sha256(password.encode()).hexdigest()
    user = (db_session.query(UserAuth)
            .filter(UserAuth.username == username and UserAuth.password_hash == password_hash).first())

    if user is None:
        return jsonify({'error': 'Invalid Username or Password'}), 401
    if user.email_verified is False:
        send_verification_mail(mail, user.email, SECRET_KEY, SECURITY_PASSWORD_SALT)
        return jsonify({'error': 'Email not verified', 'message': 'Verify your email to login'}), 401

    access_token = create_access_token(identity=username)
    return jsonify({'success': True, 'token': access_token})


@app.route('/register', methods=['POST'])
def register():
    email = request.json['email'].lower()
    user = db_session.query(UserAuth).filter(UserAuth.email == email).first()
    if user:
        return jsonify({'error': 'A user with this email exists already'}), 400

    username = request.json['username'].lower()
    user = db_session.query(UserAuth).filter(UserAuth.username == username).first()
    if user:
        return jsonify({'error': 'Username already exists'}), 400

    password = request.json['password']
    if check_strong_password(password) is False:
        return jsonify({'error': 'Password is too weak'}), 400

    password_hash = sha256(password.encode()).hexdigest()
    new_user = UserAuth(username=username, password_hash=password_hash, email=email)

    # email verification
    send_verification_mail(mail, email, SECRET_KEY, SECURITY_PASSWORD_SALT)

    db_session.add(new_user)
    db_session.commit()

    return jsonify({'message': "Click the link in your email to verify your email"})


@app.route('/change_password/<token>', methods=['POST'])
def change_password(token):
    email = confirm_token(token, SECRET_KEY, SECURITY_PASSWORD_SALT)
    if email is False:
        return 'The confirmation link is invalid or has expired.'

    username = request.json['username'].lower()
    user = db_session.query(UserAuth).filter(UserAuth.username == username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    old_password = request.json.get('old_password')
    if old_password is None:
        return jsonify({'error': 'Missing old password'}), 400

    old_password_hash = sha256(old_password.encode()).hexdigest()
    if user.password_hash != old_password_hash:
        return jsonify({'error': 'Invalid password'}), 401

    new_password = request.json.get('new_password')
    if new_password is None:
        return jsonify({'error': 'Missing new password'}), 400

    if check_strong_password(new_password) is False:
        return jsonify({'error': 'Password is too weak'}), 400

    new_password_hash = sha256(new_password.encode()).hexdigest()
    user.password_hash = new_password_hash
    db_session.commit()

    return jsonify({'success': True})


@app.route('/reset_password_via_email', methods=['POST'])
def reset_password_via_email():
    email = request.json['email'].lower()
    user = db_session.query(UserAuth).filter(UserAuth.email == email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    send_password_verification_mail(mail, email, SECRET_KEY, SECURITY_PASSWORD_SALT)
    return jsonify({'message': 'Password reset email sent'})


@app.route('/confirm-email/<token>', methods=['GET'])
def confirm_email(token):
    email = confirm_token(token, SECRET_KEY, SECURITY_PASSWORD_SALT)
    if email is False:
        return 'The confirmation link is invalid or has expired.'
    user = db_session.query(UserAuth).filter(UserAuth.email == email).first()

    if user is None:
        return jsonify({'error': 'User not found'}), 404

    user.email_verified = True
    db_session.commit()
    return 'Email confirmed!'


@app.route('/verify-email', methods=['POST'])
def verify_email():
    email = request.json['email'].lower()
    user = db_session.query(UserAuth).filter(UserAuth.email == email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    send_verification_mail(mail, email, SECRET_KEY, SECURITY_PASSWORD_SALT)

    return jsonify({'message': 'Email verification sent'})


@app.route('/get-qrs', methods=['GET'])
@jwt_required()
def get_qrs():
    page = request.args.get('page', 1, type=int)

    qrs = (db_session.query(QRInfo).filter(QRInfo.username == current_user.username).order_by(QRInfo.created_at)
           .limit(QR_ITEMS_PER_PAGE).offset((page - 1) * QR_ITEMS_PER_PAGE)).all()

    return jsonify({'message': 'Success', 'qrs': qrs})


@app.route('/add-qrs', methods=['POST'])
@jwt_required()
def add_qrs():
    username = current_user.username
    raw_data = request.json['raw_data']
    qr_type = request.json['type']

    new_qr = QRInfo(username=username, raw_data=raw_data, type=qr_type)
    db_session.add(new_qr)
    db_session.commit()

    return jsonify({'message': 'QR added'})


@app.route('/delete-qr/<qr_id>', methods=['DELETE'])
@jwt_required()
def delete_qr(qr_id):
    qr = db_session.query(QRInfo).filter(QRInfo.id == qr_id).first()
    if qr is None:
        return jsonify({'error': 'QR not found'}), 404

    db_session.delete(qr)
    db_session.commit()

    return jsonify({'message': 'QR deleted'})


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    user = db_session.query(UserAuth).filter(UserAuth.username == identity).first()
    return user


if __name__ == '__main__':
    app.run()
