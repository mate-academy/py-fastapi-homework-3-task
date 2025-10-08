from __future__ import annotations

import datetime as dt
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator

from database.models.movies import MovieStatusEnum
from schemas.examples.movies import (
    country_schema_example,
    language_schema_example,
    genre_schema_example,
    actor_schema_example,
    movie_item_schema_example,
    movie_list_response_schema_example,
    movie_create_schema_example,
    movie_detail_schema_example,
    movie_update_schema_example,
)


class LanguageSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [language_schema_example]},
    }


class CountrySchema(BaseModel):
    id: int
    code: str
    name: Optional[str]

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [country_schema_example]},
    }


class GenreSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [genre_schema_example]},
    }


class ActorSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [actor_schema_example]},
    }


# ---------- Brief / List item ----------
class MovieBriefSchema(BaseModel):
    id: int
    name: str
    date: dt.date
    score: float
    overview: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_item_schema_example]},
    }


MovieListItemSchema = MovieBriefSchema


# ---------- Full movie ----------
class MovieFullSchema(BaseModel):
    id: int
    name: str
    date: dt.date
    score: float = Field(..., ge=0, le=100)
    overview: str
    status: MovieStatusEnum
    budget: Optional[float] = Field(default=None, ge=0)
    revenue: Optional[float] = Field(default=None, ge=0)
    country: Optional[CountrySchema] = None
    genres: List[GenreSchema] = Field(default_factory=list)
    actors: List[ActorSchema] = Field(default_factory=list)
    languages: List[LanguageSchema] = Field(default_factory=list)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_detail_schema_example]},
    }


MovieDetailSchema = MovieFullSchema


# ---------- List response with pagination ----------
class MovieListResponseSchema(BaseModel):
    movies: List[MovieBriefSchema]
    prev_page: Optional[str]
    next_page: Optional[str]
    total_pages: int
    total_items: int

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_list_response_schema_example]},
    }


MoviesListResponse = MovieListResponseSchema


# ---------- Create / Update ----------
class MovieCreateSchema(BaseModel):
    name: str
    date: dt.date
    score: float = Field(..., ge=0, le=100)
    overview: str
    status: MovieStatusEnum
    budget: float = Field(..., ge=0)
    revenue: float = Field(..., ge=0)
    country: str
    genres: List[str] = Field(default_factory=list)
    actors: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_create_schema_example]},
    }

    @field_validator("date")
    @classmethod
    def validate_date(cls, v: dt.date) -> dt.date:
        if v > (dt.date.today() + dt.timedelta(days=365)):
            raise ValueError("date must not be more than one year in the future")
        return v

    @field_validator("country", mode="before")
    @classmethod
    def normalize_country(cls, v: str) -> str:
        return (v or "").upper()

    @field_validator("genres", "actors", "languages", mode="before")
    @classmethod
    def normalize_list_fields(cls, v):
        if v is None:
            return []
        return [str(item).strip().title() for item in v]


class MovieUpdateSchema(BaseModel):
    name: Optional[str] = None
    date: Optional[dt.date] = None
    score: Optional[float] = Field(default=None, ge=0, le=100)
    overview: Optional[str] = None
    status: Optional[MovieStatusEnum] = None
    budget: Optional[float] = Field(default=None, ge=0)
    revenue: Optional[float] = Field(default=None, ge=0)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_update_schema_example]},
    }

    @field_validator("date")
    @classmethod
    def validate_date(cls, v: Optional[dt.date]) -> Optional[dt.date]:
        if v and v > (dt.date.today() + dt.timedelta(days=365)):
            raise ValueError("date must not be more than one year in the future")
        return v
