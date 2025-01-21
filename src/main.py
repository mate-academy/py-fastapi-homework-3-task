from fastapi import FastAPI
from src.routes import movie_router, accounts_router

app = FastAPI(
    debug=True,
    title="Movies homework",
    description="Description of project"
)

api_version_prefix = "/api/v1"

app.include_router(accounts_router,
                   prefix=f"{api_version_prefix}/accounts",
                   tags=["accounts"])
app.include_router(movie_router,
                   prefix=f"{api_version_prefix}/theater",
                   tags=["theater"])
