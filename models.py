from sqlalchemy import String , Text , Integer , DateTime , func , Boolean 
from sqlalchemy.orm import DeclarativeBase , Mapped , mapped_column 
from datetime import datetime 

class Base(DeclarativeBase):
    pass 

class Users(Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer(), primary_key=True , autoincrement=True)
    
    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    code_expires_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
     