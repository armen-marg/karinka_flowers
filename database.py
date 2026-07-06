from sqlalchemy.ext.asyncio import create_async_engine , async_sessionmaker , AsyncSession
import os 
from dotenv import load_dotenv 

load_dotenv()

engine = create_async_engine(
    os.getenv("DATABASE"), echo= True
)

SessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False,
    autoflush=False,
    class_=AsyncSession
)

async def get_session():
    async with SessionLocal() as session:
        yield session
        
        