from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


class Base(DeclarativeBase):
    pass


class UserAuth(Base):
    __tablename__ = "user_auth"
    username: Mapped[str] = mapped_column('username', String(30), primary_key=True)
    email: Mapped[str] = mapped_column('email', String(128), primary_key=True, default=None)
    password_hash: Mapped[str] = mapped_column('p_hash', String(128))
    email_verified: Mapped[bool] = mapped_column('email_verified', String(128), default=False)

    def __repr__(self) -> str:
        return (f"UserAuth(username={self.username}, password_hash={self.password_hash},"
                f" email_verified={self.email_verified}, email={self.email})")
