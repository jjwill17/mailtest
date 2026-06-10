# api/models.py
from sqlalchemy import Column, Integer, Text, DateTime, JSON
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB  # Better for JSON
from database import Base


class TestEmail(Base):
    __tablename__ = "test_emails"

    id = Column(Integer, primary_key=True, index=True)
    subject = Column(Text, nullable=True)
    raw_message = Column(Text, nullable=False)
    raw_message_b64 = Column(Text, nullable=True)
    parsed_headers = Column(JSONB, nullable=True)  # JSONB is better
    mime_tree = Column(JSONB, nullable=True)
    auth_results = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    links = Column(JSONB, nullable=True)
    images = Column(JSONB, nullable=True)
    deliverability = Column(JSONB, nullable=True)
    source = Column(Text, nullable=True, index=True)

