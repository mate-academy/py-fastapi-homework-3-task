from fastapi import FastAPI
from routes.movies import router as movies_router
from routes.accounts import router as accounts_router

app = FastAPI(title="Movies homework", description="Description of project")
api_version_prefix = "/api/v1"

app.include_router(movies_router, prefix=f"{api_version_prefix}/theater", tags=["theater"])
app.include_router(accounts_router, prefix=f"{api_version_prefix}", tags=["accounts"])
