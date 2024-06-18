from sqlalchemy import Column, Integer, String, Date, ForeignKey, Text, DECIMAL, TIMESTAMP
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = 'users'
    UserID = Column(Integer, primary_key=True, autoincrement=True)
    FirstName = Column(String(50))
    LastName = Column(String(50))
    Email = Column(String(100), unique=True)
    Password = Column(String(255))
    Phone = Column(String(20))
    DateOfBirth = Column(Date)
    CreatedDate = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')
    UpdatedDate = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP', onupdate='CURRENT_TIMESTAMP')
    bookings = relationship('Booking', back_populates='user')
    reviews = relationship('Review', back_populates='user')
    roles = relationship('UserRole', back_populates='user')

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

class Booking(Base):
    __tablename__ = 'bookings'
    BookingID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('users.UserID'))
    PackageID = Column(Integer, ForeignKey('packages.PackageID'))
    BookingDate = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')
    Status = Column(String(50))
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
    ReviewDate = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')
    user = relationship('User', back_populates='reviews')
    package = relationship('Package', back_populates='reviews')

class Payment(Base):
    __tablename__ = 'payments'
    PaymentID = Column(Integer, primary_key=True, autoincrement=True)
    BookingID = Column(Integer, ForeignKey('bookings.BookingID'))
    PaymentDate = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')
    Amount = Column(DECIMAL(10, 2))
    PaymentMethod = Column(String(50))
    Status = Column(String(50))
    booking = relationship('Booking', back_populates='payment')
