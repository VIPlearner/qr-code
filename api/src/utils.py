from sqlalchemy import Table, MetaData, Column, Boolean, Integer, String, text, Enum
from sqlalchemy.exc import NoSuchTableError


def check_strong_password(password: str) -> bool:
    """
    Check if a password is strong enough also check for special character
    :param password: Password to check
    :return: True if the password is strong enough
    """
    return (len(password) >= 8 and any(char.isdigit() for char in password) and
            any(char.isupper() for char in password) and any(
                char.islower() for char in password) and any(char.isascii() for char in password) and any(
                char in "!@#$%^&*()-+" for char in password))


def init_db(engine, session):
    metadata = MetaData()

    # # Drop the table
    # session.execute(text('DROP TABLE user_auth;'))
    # session.commit()

    # user_auth
    try:
        user_auth = Table('user_auth', metadata, autoload_with=engine)
    except NoSuchTableError:
        user_auth = Table(
            'user_auth',
            metadata,
            Column('username', String(255), primary_key=True),
            Column('email', String(255), primary_key=True),
            Column('p_hash', String(255)),
            Column('email_verified', Boolean, default=False)
        )
        metadata.create_all(engine)

    for column_name, column_type, default in [('username', 'VARCHAR(255)', ''), ('email', 'VARCHAR(255)', ''),
                                              ('p_hash', 'VARCHAR(255)', ''), ('email_verified', 'BOOLEAN', False)]:
        if user_auth.columns.get(column_name) is None:
            session.execute(text(f"ALTER TABLE user_auth ADD COLUMN {column_name} {column_type} DEFAULT {default};"))
            session.commit()

    try:
        qr_info = Table('qr_info', metadata, autoload_with=engine)
    except NoSuchTableError:
        qr_info = Table(
            'qr_info',
            metadata,
            Column('id', String(255), primary_key=True),
            Column('username', String(255)),
            Column('raw_data', String(255)),
            Column('type', Enum('website', 'wifi', 'text', 'contact', 'email', 'sms',
                                'phone', 'whatsapp', 'instagram', name='qr_type')),
            Column('created_at', Integer)
        )
        metadata.create_all(engine)

    for column_name, column_type, default in [('id', 'VARCHAR(255)', ''), ('username', 'VARCHAR(255)', ''),
                                              ('raw_data', 'VARCHAR(255)', ''), ('type', 'qr_type', ''),
                                              ('created_at', 'INTEGER', 0)]:
        if qr_info.columns.get(column_name) is None:
            session.execute(text(f"ALTER TABLE qr_info ADD COLUMN {column_name} {column_type} DEFAULT {default};"))
            session.commit()
