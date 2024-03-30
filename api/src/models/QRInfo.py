from enum import Enum as PyEnum
from sqlalchemy import String, Boolean, Enum, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class QRType(PyEnum):
    WEBSITE = 'website'
    WIFI = 'wifi'
    TEXT = 'text'
    CONTACT = 'contact'
    EMAIL = 'email'
    SMS = 'sms'
    PHONE = 'phone'
    WHATSAPP = 'whatsapp'
    INSTAGRAM = 'instagram'


class Base(DeclarativeBase):
    pass


class QRInfo(Base):
    __tablename__ = "qr_info"
    id: Mapped[str] = mapped_column('id', String(255), primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column('username', String(30))
    raw_data: Mapped[str] = mapped_column('raw_data', String(30))
    type: Mapped[PyEnum] = mapped_column('type', Enum(QRType, name='qr_type'))
    created_at: Mapped[int] = mapped_column('created_at', Integer)

    def __repr__(self) -> str:
        return (f"QRInfo(raw_data={self.raw_data}, type={self.type},"
                f" time={self.time})")
