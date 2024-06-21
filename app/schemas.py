from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import date, datetime

from app.models import BookingStatus

class UserBase(BaseModel):
    FirstName: str
    LastName: str
    username: str
    Email: EmailStr
    Phone: str
    DateOfBirth: date

class UserCreate(UserBase):
    Password: str
    Role: Optional[str] = "user"

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
    Status: BookingStatus
    NumberOfPeople: int

class BookingCreate(BookingBase):
    pass

class BookingInDB(BaseModel):
    BookingID: int
    BookingDate: datetime
    UserEmail: Optional[str]
    UserFirstName: Optional[str]
    UserLastName: Optional[str]

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

class PackageReviews(BaseModel):
    average_rating: float
    reviews: List[ReviewInDB]

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

class SessionTokenBase(BaseModel):
    token: str = Field(..., description="The unique token")
    session_token: str = Field(..., description="The unique session token")

class SessionTokenCreate(SessionTokenBase):
    pass

class SessionToken(SessionTokenBase):
    user_id: Optional[int] = Field(None, description="The ID of the user this token is associated with")
    super_admin_id: Optional[int] = Field(None, description="The ID of the admin this token is associated with")
    expiry_date: Optional[datetime] = Field(None, description="The expiration date of the token")

    class Config:
        orm_mode = True


class TokenData(BaseModel):
    email: str or None = None


class ForgotPassword(BaseModel):
    email: EmailStr


class PasswordResetBase(BaseModel):
    reset_token: str = Field(..., description="The unique password reset token")


class PasswordResetCreate(PasswordResetBase):
    # If there are additional fields needed during the creation of a password reset token
    pass


class PasswordReset(PasswordResetBase):
    user_id: int = Field(..., description="The ID of the user requesting the password reset")
    expiry_date: Optional[datetime] = Field(None, description="The expiration date of the reset token")
    created_at: Optional[datetime] = Field(None, description="The date and time when the reset request was created")
    is_used: bool = Field(False, description="If it's true the token will be deleted")

    class Config:
        orm_mode = True


class AccountActivationBase(BaseModel):
    activation_token: str = Field(..., description="The activation token sent to the user's email")


class AccountActivationCreate(AccountActivationBase):
    # This schema could be used when generating a new token
    pass


class AccountActivationVerify(BaseModel):
    activation_token: str = Field(..., description="The token provided by the user for verification")


class AccountActivation(BaseModel):
    id: int
    user_id: int
    activation_token: str
    expiry_date: datetime
    created_at: datetime

    class Config:
        orm_mode = True


class VerifyCodeRequest(BaseModel):
    email: str
    code: str


class Message(BaseModel):
    message: str


class SuccessMessage(BaseModel):
    success: bool
    status_code: int
    message: str


class ResetForgetPassword(BaseModel):
    secret_token: str
    new_password: str
    confirm_password: str
