from datetime import date, datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator

from database.models.movies import MovieStatusEnum
from schemas.examples.movies import (
    actor_schema_example,
    country_schema_example,
    genre_schema_example,
    language_schema_example,
    movie_create_schema_example,
    movie_detail_schema_example,
    movie_item_schema_example,
    movie_list_response_schema_example,
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
    name: str | None

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


class MovieBaseSchema(BaseModel):
    name: str = Field(..., max_length=255)
    date: date
    score: float = Field(..., ge=0, le=100)
    overview: str
    status: MovieStatusEnum
    budget: float = Field(..., ge=0)
    revenue: float = Field(..., ge=0)

    model_config = {"from_attributes": True}

    @field_validator("date")
    @classmethod
    def validate_date(cls, value):
        current_year = datetime.now().year
        if value.year > current_year + 1:
            raise ValueError(
                f"The year in 'date' cannot be greater than {current_year + 1}."
            )
        return value


class MovieDetailSchema(MovieBaseSchema):
    id: int
    country: CountrySchema
    genres: list[GenreSchema]
    actors: list[ActorSchema]
    languages: list[LanguageSchema]

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_detail_schema_example]},
    }


class MovieListItemSchema(BaseModel):
    id: int
    name: str
    date: date
    score: float
    overview: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_item_schema_example]},
    }


class MovieListResponseSchema(BaseModel):
    movies: list[MovieListItemSchema]
    prev_page: str | None
    next_page: str | None
    total_pages: int
    total_items: int

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_list_response_schema_example]},
    }


class MovieCreateSchema(BaseModel):
    name: str
    date: date
    score: float = Field(..., ge=0, le=100)
    overview: str
    status: MovieStatusEnum
    budget: float = Field(..., ge=0)
    revenue: float = Field(..., ge=0)
    country: str
    genres: list[str]
    actors: list[str]
    languages: list[str]

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_create_schema_example]},
    }

    @field_validator("country", mode="before")
    @classmethod
    def normalize_country(cls, value: str) -> str:
        return value.upper()

    @field_validator("genres", "actors", "languages", mode="before")
    @classmethod
    def normalize_list_fields(cls, value: list[str]) -> list[str]:
        return [item.title() for item in value]


class MovieUpdateSchema(BaseModel):
    name: str | None = None
    date: Optional[date] = None
    score: float | None = Field(None, ge=0, le=100)
    overview: str | None = None
    status: MovieStatusEnum | None = None
    budget: float | None = Field(None, ge=0)
    revenue: float | None = Field(None, ge=0)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_update_schema_example]},
    }
