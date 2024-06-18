from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import date, datetime

class UserBase(BaseModel):
    FirstName: str
    LastName: str
    Email: EmailStr
    Phone: str
    DateOfBirth: date

class UserCreate(UserBase):
    Password: str

class UserUpdate(UserBase):
    pass

class UserInDB(UserBase):
    UserID: int
    CreatedDate: datetime
    UpdatedDate: datetime

    class Config:
        orm_mode = True

class RoleBase(BaseModel):
    RoleName: str

class RoleCreate(RoleBase):
    pass

class RoleInDB(RoleBase):
    RoleID: int

    class Config:
        orm_mode = True

class UserRoleBase(BaseModel):
    UserID: int
    RoleID: int

class UserRoleCreate(UserRoleBase):
    pass

class UserRoleInDB(UserRoleBase):
    UserRoleID: int

    class Config:
        orm_mode = True

class DestinationBase(BaseModel):
    DestinationName: str
    Country: str
    Description: Optional[str] = None

class DestinationCreate(DestinationBase):
    pass

class DestinationInDB(DestinationBase):
    DestinationID: int

    class Config:
        orm_mode = True

class PackageBase(BaseModel):
    PackageName: str
    Description: str
    Price: float
    Duration: int
    StartDate: date
    EndDate: date
    DestinationID: int

class PackageCreate(PackageBase):
    pass

class PackageInDB(PackageBase):
    PackageID: int

    class Config:
        orm_mode = True

class BookingBase(BaseModel):
    UserID: int
    PackageID: int
    Status: str
    NumberOfPeople: int

class BookingCreate(BookingBase):
    pass

class BookingInDB(BookingBase):
    BookingID: int
    BookingDate: datetime

    class Config:
        orm_mode = True

class ReviewBase(BaseModel):
    UserID: int
    PackageID: int
    Rating: int
    Comment: str

class ReviewCreate(ReviewBase):
    pass

class ReviewInDB(ReviewBase):
    ReviewID: int
    ReviewDate: datetime

    class Config:
        orm_mode = True

class PaymentBase(BaseModel):
    BookingID: int
    Amount: float
    PaymentMethod: str
    Status: str

class PaymentCreate(PaymentBase):
    pass

class PaymentInDB(PaymentBase):
    PaymentID: int
    PaymentDate: datetime

    class Config:
        orm_mode = True
