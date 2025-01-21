import random

import pytest

from database import MovieModel
from database import GenreModel, ActorModel, LanguageModel, CountryModel


def test_get_movies_empty_database(client):
    """
    Test that the `/movies/` endpoint returns a 404 error when the database is empty.
    """
    response = client.get("/api/v1/theater/movies/")

    assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    expected_detail = {"detail": "No movies found."}
    assert (
        response.json() == expected_detail
    ), f"Expected {expected_detail}, got {response.json()}"


def test_get_movies_default_parameters(client, seed_database):
    """
    Test the `/movies/` endpoint with default pagination parameters.
    """
    response = client.get("/api/v1/theater/movies/")

    assert (
        response.status_code == 200
    ), "Expected status code 200, but got a different value"

    response_data = response.json()

    assert (
        len(response_data["movies"]) == 10
    ), "Expected 10 movies in the response, but got a different count"

    assert (
        response_data["total_pages"] > 0
    ), "Expected total_pages > 0, but got a non-positive value"

    assert (
        response_data["total_items"] > 0
    ), "Expected total_items > 0, but got a non-positive value"

    assert (
        response_data["prev_page"] is None
    ), "Expected prev_page to be None on the first page, but got a value"

    if response_data["total_pages"] > 1:
        assert (
            response_data["next_page"] is not None
        ), "Expected next_page to be present when total_pages > 1, but got None"


def test_get_movies_with_custom_parameters(client, seed_database):
    """
    Test the `/movies/` endpoint with custom pagination parameters.
    """
    page = 2
    per_page = 5

    response = client.get(f"/api/v1/theater/movies/?page={page}&per_page={per_page}")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    assert (
        len(response_data["movies"]) == per_page
    ), f"Expected {per_page} movies in the response, but got {len(response_data['movies'])}"

    assert (
        response_data["total_pages"] > 0
    ), "Expected total_pages > 0, but got a non-positive value"

    assert (
        response_data["total_items"] > 0
    ), "Expected total_items > 0, but got a non-positive value"

    if page > 1:
        assert (
            response_data["prev_page"]
            == f"/theater/movies/?page={page - 1}&per_page={per_page}"
        ), (
            f"Expected prev_page to be '/theater/movies/?page={page - 1}&per_page={per_page}', "
            f"but got {response_data['prev_page']}"
        )

    if page < response_data["total_pages"]:
        assert (
            response_data["next_page"]
            == f"/theater/movies/?page={page + 1}&per_page={per_page}"
        ), (
            f"Expected next_page to be '/theater/movies/?page={page + 1}&per_page={per_page}', "
            f"but got {response_data['next_page']}"
        )
    else:
        assert (
            response_data["next_page"] is None
        ), "Expected next_page to be None on the last page, but got a value"


@pytest.mark.parametrize(
    "page, per_page, expected_detail",
    [
        (0, 10, "Input should be greater than or equal to 1"),
        (1, 0, "Input should be greater than or equal to 1"),
        (0, 0, "Input should be greater than or equal to 1"),
    ],
)
def test_invalid_page_and_per_page(client, page, per_page, expected_detail):
    """
    Test the `/movies/` endpoint with invalid `page` and `per_page` parameters.
    """
    response = client.get(f"/api/v1/theater/movies/?page={page}&per_page={per_page}")

    assert (
        response.status_code == 422
    ), f"Expected status code 422 for invalid parameters, but got {response.status_code}"

    response_data = response.json()

    assert (
        "detail" in response_data
    ), "Expected 'detail' in the response, but it was missing"

    assert any(
        expected_detail in error["msg"] for error in response_data["detail"]
    ), f"Expected error message '{expected_detail}' in the response details, but got {response_data['detail']}"


def test_per_page_maximum_allowed_value(client, seed_database):
    """
    Test the `/movies/` endpoint with the maximum allowed `per_page` value.
    """
    response = client.get("/api/v1/theater/movies/?page=1&per_page=20")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    assert "movies" in response_data, "Response missing 'movies' field."
    assert (
        len(response_data["movies"]) <= 20
    ), f"Expected at most 20 movies, but got {len(response_data['movies'])}"


def test_page_exceeds_maximum(client, db_session, seed_database):
    """
    Test the `/movies/` endpoint with a page number that exceeds the maximum.
    """
    per_page = 10
    total_movies = db_session.query(MovieModel).count()
    max_page = (total_movies + per_page - 1) // per_page

    response = client.get(
        f"/api/v1/theater/movies/?page={max_page + 1}&per_page={per_page}"
    )

    assert (
        response.status_code == 404
    ), f"Expected status code 404, but got {response.status_code}"

    response_data = response.json()

    assert "detail" in response_data, "Response missing 'detail' field."


def test_movies_sorted_by_id_desc(client, db_session, seed_database):
    """
    Test that movies are returned sorted by `id` in descending order
    and match the expected data from the database.
    """
    response = client.get("/api/v1/theater/movies/?page=1&per_page=10")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    expected_movies = (
        db_session.query(MovieModel).order_by(MovieModel.id.desc()).limit(10).all()
    )

    expected_movie_ids = [movie.id for movie in expected_movies]
    returned_movie_ids = [movie["id"] for movie in response_data["movies"]]

    assert returned_movie_ids == expected_movie_ids, (
        f"Movies are not sorted by `id` in descending order. "
        f"Expected: {expected_movie_ids}, but got: {returned_movie_ids}"
    )


def test_movie_list_with_pagination(client, db_session, seed_database):
    """
    Test the `/movies/` endpoint with pagination parameters.

    Verifies the following:
    - The response status code is 200.
    - Total items and total pages match the expected values from the database.
    - The movies returned match the expected movies for the given page and per_page.
    - The `prev_page` and `next_page` links are correct.
    """
    page = 2
    per_page = 5
    offset = (page - 1) * per_page

    response = client.get(f"/api/v1/theater/movies/?page={page}&per_page={per_page}")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    total_items = db_session.query(MovieModel).count()
    total_pages = (total_items + per_page - 1) // per_page
    assert response_data["total_items"] == total_items, "Total items mismatch."
    assert response_data["total_pages"] == total_pages, "Total pages mismatch."

    expected_movies = (
        db_session.query(MovieModel)
        .order_by(MovieModel.id.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )
    expected_movie_ids = [movie.id for movie in expected_movies]
    returned_movie_ids = [movie["id"] for movie in response_data["movies"]]

    assert expected_movie_ids == returned_movie_ids, "Movies on the page mismatch."

    assert response_data["prev_page"] == (
        f"/theater/movies/?page={page - 1}&per_page={per_page}" if page > 1 else None
    ), "Previous page link mismatch."
    assert response_data["next_page"] == (
        f"/theater/movies/?page={page + 1}&per_page={per_page}"
        if page < total_pages
        else None
    ), "Next page link mismatch."


def test_movies_fields_match_schema(client, db_session, seed_database):
    """
    Test that each movie in the response matches the fields defined in `MovieListItemSchema`.
    """
    response = client.get("/api/v1/theater/movies/?page=1&per_page=10")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    assert "movies" in response_data, "Response missing 'movies' field."

    expected_fields = {"id", "name", "date", "score", "overview"}

    for movie in response_data["movies"]:
        assert set(movie.keys()) == expected_fields, (
            f"Movie fields do not match schema. "
            f"Expected: {expected_fields}, but got: {set(movie.keys())}"
        )


def test_get_movie_by_id_not_found(client):
    """
    Test that the `/movies/{movie_id}` endpoint returns a 404 error
    when a movie with the given ID does not exist.
    """
    movie_id = 1

    response = client.get(f"/api/v1/theater/movies/{movie_id}")

    assert (
        response.status_code == 404
    ), f"Expected status code 404, but got {response.status_code}"

    response_data = response.json()

    assert response_data == {
        "detail": "Movie with the given ID was not found."
    }, f"Expected error message not found. Got: {response_data}"


def test_get_movie_by_id_valid(client, db_session, seed_database):
    """
    Test that the `/movies/{movie_id}` endpoint returns the correct movie details
    when a valid movie ID is provided.

    Verifies the following:
    - The movie exists in the database.
    - The response status code is 200.
    - The movie's `id` and `name` in the response match the expected values from the database.
    """
    min_id = db_session.query(MovieModel.id).order_by(MovieModel.id.asc()).first()[0]
    max_id = db_session.query(MovieModel.id).order_by(MovieModel.id.desc()).first()[0]

    random_id = random.randint(min_id, max_id)

    expected_movie = (
        db_session.query(MovieModel).filter(MovieModel.id == random_id).first()
    )
    assert expected_movie is not None, "Movie not found in database."

    response = client.get(f"/api/v1/theater/movies/{random_id}")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    assert (
        response_data["id"] == expected_movie.id
    ), "Returned ID does not match the requested ID."

    assert (
        response_data["name"] == expected_movie.name
    ), "Returned name does not match the expected name."


def test_get_movie_by_id_fields_match_database(client, db_session, seed_database):
    """
    Test that the `/movies/{movie_id}` endpoint returns all fields matching the database data.
    """
    random_movie = db_session.query(MovieModel).first()
    assert random_movie is not None, "No movies found in the database."

    response = client.get(f"/api/v1/theater/movies/{random_movie.id}/")

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()

    assert response_data["id"] == random_movie.id, "ID does not match."
    assert response_data["name"] == random_movie.name, "Name does not match."
    assert (
        response_data["date"] == random_movie.date.isoformat()
    ), "Date does not match."
    assert response_data["score"] == random_movie.score, "Score does not match."
    assert (
        response_data["overview"] == random_movie.overview
    ), "Overview does not match."
    assert (
        response_data["status"] == random_movie.status.value
    ), "Status does not match."
    assert response_data["budget"] == float(
        random_movie.budget
    ), "Budget does not match."
    assert response_data["revenue"] == random_movie.revenue, "Revenue does not match."

    assert (
        response_data["country"]["id"] == random_movie.country.id
    ), "Country ID does not match."
    assert (
        response_data["country"]["code"] == random_movie.country.code
    ), "Country code does not match."
    assert (
        response_data["country"]["name"] == random_movie.country.name
    ), "Country name does not match."

    expected_genres = sorted(
        [{"id": genre.id, "name": genre.name} for genre in random_movie.genres],
        key=lambda x: x["id"],
    )
    response_genres = sorted(response_data["genres"], key=lambda x: x["id"])
    assert response_genres == expected_genres, "Genres do not match."

    expected_actors = sorted(
        [{"id": actor.id, "name": actor.name} for actor in random_movie.actors],
        key=lambda x: x["id"],
    )
    response_actors = sorted(response_data["actors"], key=lambda x: x["id"])
    assert response_actors == expected_actors, "Actors do not match."

    expected_languages = sorted(
        [{"id": lang.id, "name": lang.name} for lang in random_movie.languages],
        key=lambda x: x["id"],
    )
    response_languages = sorted(response_data["languages"], key=lambda x: x["id"])
    assert response_languages == expected_languages, "Languages do not match."


def test_create_movie_and_related_models(client, db_session):
    """
    Test that a new movie is created successfully and related models
    (genres, actors, languages) are created if they do not exist.
    """
    movie_data = {
        "name": "New Movie",
        "date": "2025-01-01",
        "score": 85.5,
        "overview": "An amazing movie.",
        "status": "Released",
        "budget": 1000000.00,
        "revenue": 5000000.00,
        "country": "US",
        "genres": ["Action", "Adventure"],
        "actors": ["John Doe", "Jane Doe"],
        "languages": ["English", "French"],
    }

    response = client.post("/api/v1/theater/movies/", json=movie_data)

    assert (
        response.status_code == 201
    ), f"Expected status code 201, but got {response.status_code}"

    response_data = response.json()

    assert response_data["name"] == movie_data["name"], "Movie name does not match."
    assert response_data["date"] == movie_data["date"], "Movie date does not match."
    assert response_data["score"] == movie_data["score"], "Movie score does not match."
    assert (
        response_data["overview"] == movie_data["overview"]
    ), "Movie overview does not match."

    for genre_name in movie_data["genres"]:
        genre = db_session.query(GenreModel).filter_by(name=genre_name).first()
        assert genre is not None, f"Genre '{genre_name}' was not created."

    for actor_name in movie_data["actors"]:
        actor = db_session.query(ActorModel).filter_by(name=actor_name).first()
        assert actor is not None, f"Actor '{actor_name}' was not created."

    for language_name in movie_data["languages"]:
        language = db_session.query(LanguageModel).filter_by(name=language_name).first()
        assert language is not None, f"Language '{language_name}' was not created."

    country = (
        db_session.query(CountryModel).filter_by(code=movie_data["country"]).first()
    )
    assert country is not None, f"Country '{movie_data['country']}' was not created."


def test_create_movie_duplicate_error(client, db_session, seed_database):
    """
    Test that trying to create a movie with the same name and date as an existing movie
    results in a 409 conflict error.
    """
    existing_movie = db_session.query(MovieModel).first()
    assert existing_movie is not None, "No existing movies found in the database."

    movie_data = {
        "name": existing_movie.name,
        "date": existing_movie.date.isoformat(),
        "score": 90.0,
        "overview": "Duplicate movie test.",
        "status": "Released",
        "budget": 2000000.00,
        "revenue": 8000000.00,
        "country": "US",
        "genres": ["Drama"],
        "actors": ["New Actor"],
        "languages": ["Spanish"],
    }

    response = client.post("/api/v1/theater/movies/", json=movie_data)

    assert (
        response.status_code == 409
    ), f"Expected status code 409, but got {response.status_code}"

    response_data = response.json()

    expected_detail = f"A movie with the name '{movie_data['name']}' and release date '{movie_data['date']}' already exists."
    assert (
        response_data["detail"] == expected_detail
    ), f"Expected detail message: {expected_detail}, but got: {response_data['detail']}"


def test_delete_movie_success(client, db_session, seed_database):
    """
    Test the `/movies/{movie_id}/` endpoint for successful movie deletion.
    """
    movie = db_session.query(MovieModel).first()
    assert movie is not None, "No movies found in the database to delete."

    movie_id = movie.id

    response = client.delete(f"/api/v1/theater/movies/{movie_id}/")

    assert (
        response.status_code == 204
    ), f"Expected status code 204, but got {response.status_code}"

    deleted_movie = (
        db_session.query(MovieModel).filter(MovieModel.id == movie_id).first()
    )
    assert deleted_movie is None, f"Movie with ID {movie_id} was not deleted."


def test_delete_movie_not_found(client):
    """
    Test the `/movies/{movie_id}/` endpoint with a non-existent movie ID.
    """
    non_existent_id = 99999

    response = client.delete(f"/api/v1/theater/movies/{non_existent_id}/")

    assert (
        response.status_code == 404
    ), f"Expected status code 404, but got {response.status_code}"

    response_data = response.json()
    expected_detail = "Movie with the given ID was not found."
    assert (
        response_data["detail"] == expected_detail
    ), f"Expected detail message: {expected_detail}, but got: {response_data['detail']}"


def test_update_movie_success(client, db_session, seed_database):
    """
    Test the `/movies/{movie_id}/` endpoint for successfully updating a movie's details.
    """
    movie = db_session.query(MovieModel).first()
    assert movie is not None, "No movies found in the database to update."

    movie_id = movie.id
    update_data = {
        "name": "Updated Movie Name",
        "score": 95.0,
    }

    response = client.patch(f"/api/v1/theater/movies/{movie_id}/", json=update_data)

    assert (
        response.status_code == 200
    ), f"Expected status code 200, but got {response.status_code}"

    response_data = response.json()
    assert (
        response_data["detail"] == "Movie updated successfully."
    ), f"Expected detail message: 'Movie updated successfully.', but got: {response_data['detail']}"

    db_session.expire_all()
    updated_movie = (
        db_session.query(MovieModel).filter(MovieModel.id == movie_id).first()
    )

    assert updated_movie.name == update_data["name"], "Movie name was not updated."
    assert updated_movie.score == update_data["score"], "Movie score was not updated."


def test_update_movie_not_found(client):
    """
    Test the `/movies/{movie_id}/` endpoint with a non-existent movie ID.
    """
    non_existent_id = 99999
    update_data = {"name": "Non-existent Movie", "score": 90.0}

    response = client.patch(
        f"/api/v1/theater/movies/{non_existent_id}/", json=update_data
    )

    assert (
        response.status_code == 404
    ), f"Expected status code 404, but got {response.status_code}"

    response_data = response.json()
    expected_detail = "Movie with the given ID was not found."
    assert (
        response_data["detail"] == expected_detail
    ), f"Expected detail message: {expected_detail}, but got: {response_data['detail']}"
