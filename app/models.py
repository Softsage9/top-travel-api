from enum import Enum
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Date, ForeignKey, Text, DECIMAL, TIMESTAMP, func, Enum as SQLAEnum
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = 'users'
    UserID = Column(Integer, primary_key=True, autoincrement=True)
    google_id = Column(String(255), unique=True, index=True, nullable=True)
    FirstName = Column(String(50))
    LastName = Column(String(50))
    username = Column(String(50), unique=True)
    Email = Column(String(100), unique=True)
    Password = Column(String(255))
    Phone = Column(String(20))
    DateOfBirth = Column(Date)
    CreatedDate = Column(TIMESTAMP, server_default=func.now())
    UpdatedDate = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    bookings = relationship('Booking', back_populates='user')
    reviews = relationship('Review', back_populates='user')
    roles = relationship('UserRole', back_populates='user')
    disabled = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    account_activation = relationship("AccountActivation", uselist=False, back_populates="user")

class Role(Base):
    __tablename__ = 'roles'
    RoleID = Column(Integer, primary_key=True, autoincrement=True)
    RoleName = Column(String(50))
    users = relationship('UserRole', back_populates='role')

class UserRole(Base):
    __tablename__ = 'user_roles'
    UserRoleID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('users.UserID'))
    RoleID = Column(Integer, ForeignKey('roles.RoleID'))
    user = relationship('User', back_populates='roles')
    role = relationship('Role', back_populates='users')

class SessionToken(Base):
    __tablename__ = 'session_tokens'

    token = Column(String(255), primary_key=True)
    session_token = Column(String(255))
    user_id = Column(Integer, ForeignKey('users.UserID'), nullable=True)
    expiry_date = Column(DateTime)


class PasswordReset(Base):
    __tablename__ = 'password_resets'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.UserID'))
    reset_token = Column(String(255), unique=True)
    expiry_date = Column(DateTime)
    is_used = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class AccountActivation(Base):
    __tablename__ = 'account_activations'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.UserID'), unique=True)
    activation_token = Column(String(255), unique=True, index=True)
    expiry_date = Column(DateTime)
    created_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="account_activation")
class Destination(Base):
    __tablename__ = 'destinations'
    DestinationID = Column(Integer, primary_key=True, autoincrement=True)
    DestinationName = Column(String(100))
    Country = Column(String(50))
    Description = Column(Text)
    packages = relationship('Package', back_populates='destination')

class Package(Base):
    __tablename__ = 'packages'
    PackageID = Column(Integer, primary_key=True, autoincrement=True)
    PackageName = Column(String(100))
    Description = Column(Text)
    Price = Column(DECIMAL(10, 2))
    Duration = Column(Integer)
    StartDate = Column(Date)
    EndDate = Column(Date)
    DestinationID = Column(Integer, ForeignKey('destinations.DestinationID'))
    destination = relationship('Destination', back_populates='packages')
    bookings = relationship('Booking', back_populates='package')
    reviews = relationship('Review', back_populates='package')

class BookingStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
class Booking(Base):
    __tablename__ = 'bookings'
    BookingID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('users.UserID'))
    PackageID = Column(Integer, ForeignKey('packages.PackageID'))
    BookingDate = Column(TIMESTAMP, server_default=func.now())
    Status = Column(SQLAEnum(BookingStatus), default=BookingStatus.PENDING)
    NumberOfPeople = Column(Integer)
    user = relationship('User', back_populates='bookings')
    package = relationship('Package', back_populates='bookings')
    payment = relationship('Payment', back_populates='booking', uselist=False)
class Review(Base):
    __tablename__ = 'reviews'
    ReviewID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('users.UserID'))
    PackageID = Column(Integer, ForeignKey('packages.PackageID'))
    Rating = Column(Integer)
    Comment = Column(Text)
    ReviewDate = Column(TIMESTAMP, server_default=func.now())
    user = relationship('User', back_populates='reviews')
    package = relationship('Package', back_populates='reviews')

class Payment(Base):
    __tablename__ = 'payments'
    PaymentID = Column(Integer, primary_key=True, autoincrement=True)
    BookingID = Column(Integer, ForeignKey('bookings.BookingID'))
    PaymentDate = Column(TIMESTAMP, server_default=func.now())
    Amount = Column(DECIMAL(10, 2))
    PaymentMethod = Column(String(50))
    Status = Column(String(50))
    booking = relationship('Booking', back_populates='payment')
