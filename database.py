from sqlalchemy.ext.asyncio import create_async_engine , async_sessionmaker , AsyncSession

engine = create_async_engine(
    "mysql+aiomysql://root:Hl3trt93!@localhost/karinka_db"
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
        
        