from flask import url_for
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer

from src.config import EMAIL_USER


def confirm_token(token, secret_key: str, salt: str, expiration=3600):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(
            token,
            salt=salt,
            max_age=expiration
        )
    except:
        return False
    return email


def generate_verification_token(email: str, secret_key: str, salt: str):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt=salt)


def send_verification_mail(mail: Mail, email: str, secret_key: str, salt: str):
    token = generate_verification_token(email, secret_key, salt)

    msg = Message('Email Verification Request',
                  sender=EMAIL_USER,
                  recipients=[email])

    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg.body = f'To confirm your email, visit the following link: {confirm_url}'

    mail.send(msg)

    return 'Email verification has been sent.'


def send_password_verification_mail(mail: Mail, email: str, secret_key: str, salt: str):
    token = generate_verification_token(email, secret_key, salt)

    msg = Message('Email Verification Request',
                  sender=EMAIL_USER,
                  recipients=[email])

    confirm_url = url_for('change_password', token=token, _external=True)
    msg.body = f'To confirm your email, visit the following link: {confirm_url}'

    mail.send(msg)

    return 'Email verification has been sent.'
