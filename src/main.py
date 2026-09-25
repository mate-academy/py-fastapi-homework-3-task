from fastapi import FastAPI
from routes.accounts import router as accounts_router
from routes.movies import router as movies_router

app = FastAPI()

app.include_router(accounts_router, prefix="/api/v1/accounts", tags=["accounts"])
app.include_router(movies_router, prefix="/api/v1/theater", tags=["movies"])


@app.get("/")
def root():
    return {"status": "ok"}
