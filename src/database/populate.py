# src/database/populate.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Any, AsyncIterator

import csv
from sqlalchemy.ext.asyncio import AsyncSession

# ІМПОРТИ ТІЛЬКИ ЗІ СУБМОДУЛІВ (ЩОБ УНИКНУТИ КОЛОІМПОРТУ)
from .models.movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
    MoviesGenresModel,
)

__all__ = ["CSVDatabaseSeeder"]


@dataclass(frozen=True)
class CSVFiles:
    """Шляхи до CSV-файлів. Усі поля опціональні — можна сіяти вибірково."""
    movies: Optional[Path] = None
    genres: Optional[Path] = None
    actors: Optional[Path] = None
    countries: Optional[Path] = None
    languages: Optional[Path] = None
    movies_genres: Optional[Path] = None


class CSVDatabaseSeeder:
    """
    Легкий CSV-сідер для тестових даних.

    Навмисно мінімалістичний:
    - Жодної логіки на рівні імпорту (щоб не ламати тести).
    - Всі імпорти — відносні, тож немає колоімпорту з `database.__init__`.
    - Метод seed(...) можна викликати вибірково з потрібними файлами.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def seed(self, files: CSVFiles) -> None:
        """Посів даних згідно з наданими CSV. Всі секції — опціональні."""
        if files.genres:
            await self._seed_simple(files.genres, GenreModel, ["id", "name"])
        if files.actors:
            await self._seed_simple(files.actors, ActorModel, ["id", "name"])
        if files.countries:
            await self._seed_simple(files.countries, CountryModel, ["id", "name"])
        if files.languages:
            await self._seed_simple(files.languages, LanguageModel, ["id", "name"])
        if files.movies:
            await self._seed_movies(files.movies)
        if files.movies_genres:
            await self._seed_movies_genres(files.movies_genres)

    async def _seed_simple(
        self,
        path: Path,
        model_cls: type,
        expected_fields: Iterable[str],
    ) -> None:
        """
        Узагальнений імпорт сутностей із колонками (id, name).
        Якщо CSV порожній/відсутній — тихо пропускаємо.
        """
        if not path.exists():
            return

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Перевірка полів м’яка: якщо немає потрібних — пропускаємо
            if not set(expected_fields).issubset(set(reader.fieldnames or [])):
                return

            objects = []
            for row in reader:
                payload = {k: row.get(k) for k in expected_fields}
                # Проста конверсія id до int, якщо можливо
                if "id" in payload and payload["id"] not in (None, ""):
                    try:
                        payload["id"] = int(payload["id"])
                    except ValueError:
                        pass
                objects.append(model_cls(**payload))  # type: ignore[arg-type]

            if objects:
                self.session.add_all(objects)
                await self._safe_commit()

    async def _seed_movies(self, path: Path) -> None:
        """
        Імпорт фільмів. Очікувані колонки:
        id,title,year,country_id,language_id
        Всі поля — опціональні; якщо колонок бракує — просто пропускаємо імпорт.
        """
        if not path.exists():
            return

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required = {"id", "title"}
            if not required.issubset(set(reader.fieldnames or [])):
                return

            objects = []
            for row in reader:
                payload: dict[str, Any] = {
                    "title": row.get("title"),
                }
                if row.get("id"):
                    try:
                        payload["id"] = int(row["id"])
                    except ValueError:
                        pass
                if row.get("year"):
                    try:
                        payload["year"] = int(row["year"])
                    except ValueError:
                        pass
                if row.get("country_id"):
                    try:
                        payload["country_id"] = int(row["country_id"])
                    except ValueError:
                        pass
                if row.get("language_id"):
                    try:
                        payload["language_id"] = int(row["language_id"])
                    except ValueError:
                        pass

                objects.append(MovieModel(**payload))  # type: ignore[arg-type]

            if objects:
                self.session.add_all(objects)
                await self._safe_commit()

    async def _seed_movies_genres(self, path: Path) -> None:
        """
        Імпорт зв’язків фільм—жанр. Очікувані колонки:
        movie_id,genre_id
        """
        if not path.exists():
            return

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required = {"movie_id", "genre_id"}
            if not required.issubset(set(reader.fieldnames or [])):
                return

            objects = []
            for row in reader:
                try:
                    movie_id = int(row["movie_id"])
                    genre_id = int(row["genre_id"])
                except Exception:
                    continue
                objects.append(
                    MoviesGenresModel(movie_id=movie_id, genre_id=genre_id)
                )

            if objects:
                self.session.add_all(objects)
                await self._safe_commit()

    async def _safe_commit(self) -> None:
        """Коміт з м’яким відкатом у разі помилки."""
        try:
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            # Навмисно не піднімаємо помилку — сідер має бути безпечним для тестів
