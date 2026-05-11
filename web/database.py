import os
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///vaults.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Vault(Base):
    __tablename__ = "vaults"

    username = Column(String, primary_key=True, index=True)
    magic = Column(String)
    salt = Column(String)
    nonce = Column(String)
    ciphertext = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)

init_db()
