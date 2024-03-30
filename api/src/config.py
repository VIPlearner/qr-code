from os import environ

EMAIL_USER = environ.get('EMAIL_USER')
EMAIL_PASSWORD = environ.get('EMAIL_PASSWORD')
EMAIL_SERVER = environ.get('EMAIL_SERVER')
EMAIL_PORT = environ.get('EMAIL_PORT')
JWT_SECRET = environ.get('JWT_SECRET')
POSTGRES_DB_URI = environ.get('POSTGRES_DB_URI')
SECRET_KEY = environ.get('SECRET_KEY')
SECURITY_PASSWORD_SALT = environ.get('SECURITY_PASSWORD_SALT')
TEST = environ.get('TEST')
QR_ITEMS_PER_PAGE = 20
