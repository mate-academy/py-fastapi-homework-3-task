import pandas as pd
from sqlalchemy import insert
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from tqdm import tqdm

from config import get_settings
from database import MovieModel, get_db_contextmanager
from database import (
    CountryModel,
    GenreModel,
    ActorModel,
    MoviesGenresModel,
    ActorsMoviesModel,
    LanguageModel,
    MoviesLanguagesModel,
    UserGroupEnum,
    UserGroupModel,
)


class CSVDatabaseSeeder:
    def __init__(self, csv_file_path: str, db_session: Session):
        self._csv_file_path = csv_file_path
        self._db_session = db_session

    def is_db_populated(self) -> bool:
        return self._db_session.query(MovieModel).first() is not None

    def _seed_user_groups(self):
        """
        Seed UserGroup table with values from UserGroupEnum if the table is empty.
        """
        existing_groups = self._db_session.query(UserGroupModel).count()
        if existing_groups == 0:
            groups = [{"name": group.value} for group in UserGroupEnum]
            self._db_session.execute(insert(UserGroupModel).values(groups))
            self._db_session.flush()
            print("User groups seeded successfully.")

    def _preprocess_csv(self):
        data = pd.read_csv(self._csv_file_path)
        data = data.drop_duplicates(subset=["names", "date_x"], keep="first")

        data["crew"] = data["crew"].fillna("Unknown")
        data["crew"] = data["crew"].str.replace(r"\s+", "", regex=True)
        data["crew"] = data["crew"].apply(
            lambda crew: ",".join(sorted(set(crew.split(","))))
            if crew != "Unknown"
            else crew
        )
        data["genre"] = data["genre"].fillna("Unknown")
        data["genre"] = data["genre"].str.replace("\u00a0", "", regex=True)
        data["date_x"] = data["date_x"].str.strip()
        data["date_x"] = pd.to_datetime(
            data["date_x"], format="%Y-%m-%d", errors="raise"
        )
        data["date_x"] = data["date_x"].dt.date
        data["orig_lang"] = data["orig_lang"].str.replace(r"\s+", "", regex=True)
        data["status"] = data["status"].str.strip()
        print("Preprocessing csv file")

        data.to_csv(self._csv_file_path, index=False)
        print(f"File saved to {self._csv_file_path}")
        return data

    def _get_or_create_bulk(self, model, items: list, unique_field: str):
        existing = (
            self._db_session.query(model)
            .filter(getattr(model, unique_field).in_(items))
            .all()
        )
        existing_dict = {getattr(item, unique_field): item for item in existing}

        new_items = [item for item in items if item not in existing_dict]
        new_records = [{unique_field: item} for item in new_items]

        if new_records:
            self._db_session.execute(insert(model).values(new_records))
            self._db_session.flush()

            newly_inserted = (
                self._db_session.query(model)
                .filter(getattr(model, unique_field).in_(new_items))
                .all()
            )
            existing_dict.update(
                {getattr(item, unique_field): item for item in newly_inserted}
            )

        return existing_dict

    def seed(self):
        try:
            if self._db_session.in_transaction():
                print("Rolling back existing transaction.")
                self._db_session.rollback()

            self._seed_user_groups()

            data = self._preprocess_csv()

            countries = data["country"].unique()
            genres = set(
                genre.strip()
                for genres in data["genre"].dropna()
                for genre in genres.split(",")
                if genre.strip()
            )
            actors = set(
                actor.strip()
                for crew in data["crew"].dropna()
                for actor in crew.split(",")
                if actor.strip()
            )
            languages = set(
                lang.strip()
                for langs in data["orig_lang"].dropna()
                for lang in langs.split(",")
                if lang.strip()
            )

            country_map = self._get_or_create_bulk(CountryModel, countries, "code")
            genre_map = self._get_or_create_bulk(GenreModel, list(genres), "name")
            actor_map = self._get_or_create_bulk(ActorModel, list(actors), "name")
            language_map = self._get_or_create_bulk(
                LanguageModel, list(languages), "name"
            )

            movies_data = []
            movie_genres_data = []
            movie_actors_data = []
            movie_languages_data = []

            for _, row in tqdm(
                data.iterrows(), total=data.shape[0], desc="Processing movies"
            ):
                country = country_map[row["country"]]

                movie = {
                    "name": row["names"],
                    "date": row["date_x"],
                    "score": float(row["score"]),
                    "overview": row["overview"],
                    "status": row["status"],
                    "budget": float(row["budget_x"]),
                    "revenue": float(row["revenue"]),
                    "country_id": country.id,
                }
                movies_data.append(movie)

            result = self._db_session.execute(
                insert(MovieModel).returning(MovieModel.id), movies_data
            )
            movie_ids = result.scalars().all()

            for i, (_, row) in enumerate(
                tqdm(
                    data.iterrows(), total=data.shape[0], desc="Processing associations"
                )
            ):
                movie_id = movie_ids[i]

                for genre_name in row["genre"].split(","):
                    if genre_name.strip():
                        genre = genre_map[genre_name.strip()]
                        movie_genres_data.append(
                            {"movie_id": movie_id, "genre_id": genre.id}
                        )

                for actor_name in row["crew"].split(","):
                    if actor_name.strip():
                        actor = actor_map[actor_name.strip()]
                        movie_actors_data.append(
                            {"movie_id": movie_id, "actor_id": actor.id}
                        )

                for lang_name in row["orig_lang"].split(","):
                    if lang_name.strip():
                        language = language_map[lang_name.strip()]
                        movie_languages_data.append(
                            {"movie_id": movie_id, "language_id": language.id}
                        )

            self._db_session.execute(
                insert(MoviesGenresModel).values(movie_genres_data)
            )
            self._db_session.execute(
                insert(ActorsMoviesModel).values(movie_actors_data)
            )
            self._db_session.execute(
                insert(MoviesLanguagesModel).values(movie_languages_data)
            )
            self._db_session.commit()

        except SQLAlchemyError as e:
            print(f"An error occurred: {e}")
            raise
        except Exception as e:
            print(f"Unexpected error: {e}")
            raise


def main():
    settings = get_settings()
    with get_db_contextmanager() as db_session:
        seeder = CSVDatabaseSeeder(settings.PATH_TO_MOVIES_CSV, db_session)

        if not seeder.is_db_populated():
            try:
                seeder.seed()
                print("Database seeding completed successfully.")
            except Exception as e:
                print(f"Failed to seed the database: {e}")
        else:
            print("Database is already populated. Skipping seeding.")


if __name__ == "__main__":
    main()
