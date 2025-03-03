from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db, MovieModel
from schemas.movies import MovieSchema, CreateMovieSchema

router = APIRouter()


@router.get("/movies", response_model=list[MovieSchema])
async def get_movies(offset: int = 0, per_page: int = 10, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MovieModel).order_by(MovieModel.id).offset(offset).limit(per_page))
    movies = result.scalars().all()
    return movies


@router.get("/movies/{movie_id}", response_model=MovieSchema)
async def get_movie_by_id(movie_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MovieModel).where(MovieModel.id == movie_id))
    movie = result.scalars().first()

    if not movie:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Movie not found")

    return movie


@router.post("/movies", response_model=MovieSchema)
async def add_movie(movie_data: CreateMovieSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MovieModel).where(MovieModel.title == movie_data.title))
    existing_movie = result.scalars().first()

    if existing_movie:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Movie already exists")

    new_movie = MovieModel(**movie_data.dict())
    db.add(new_movie)
    await db.commit()
    return new_movie
