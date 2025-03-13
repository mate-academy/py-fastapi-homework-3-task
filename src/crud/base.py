from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class Base:
    model = None

    @classmethod
    async def find_by_id(cls, model_id: int, db: AsyncSession):
        query = select(cls.model).filter_by(id=model_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @classmethod
    async def find_one_or_none(cls, db: AsyncSession, **filter_by):

        query = select(cls.model).filter_by(**filter_by)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @classmethod
    async def add(cls, db: AsyncSession, **data):
        existing = await cls.find_one_or_none(db, **data)
        if existing:
            return existing

        instance = cls.model(**data)
        db.add(instance)
        await db.commit()
        await db.refresh(instance)
        return instance
