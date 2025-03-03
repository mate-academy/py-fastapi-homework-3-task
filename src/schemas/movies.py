from datetime import date, datetime
from typing import List

from pydantic import BaseModel

from database.models.movies import MovieStatusEnum


class LanguageSchema(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class CountrySchema(BaseModel):
    id: int
    name: str
    code: str

    class Config:
        from_attributes = True


class GenreSchema(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class ActorSchema(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class MovieSchema(BaseModel):
    id: int
    title: str
    description: str
    release_date: date
    rating: float
    status: MovieStatusEnum
    country: CountrySchema
    language: LanguageSchema
    genres: List[GenreSchema]
    actors: List[ActorSchema]

    class Config:
        from_attributes = True


class MovieDetailSchema(MovieSchema):
    created_at: datetime
    updated_at: datetime


class MovieListItemSchema(BaseModel):
    id: int
    title: str
    release_date: date
    rating: float


class MovieListResponseSchema(BaseModel):
    total: int
    movies: List[MovieListItemSchema]


class CreateMovieSchema(BaseModel):
    title: str
    description: str
    release_date: date
    rating: float
    status: MovieStatusEnum
    country_id: int
    language_id: int
    genre_ids: List[int]
    actor_ids: List[int]
