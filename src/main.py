from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from routes import movie_router, accounts_router

app = FastAPI(title="Movies homework", description="Description of project")

api_version_prefix = "/api/v1"

app.include_router(
    accounts_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"]
)
app.include_router(
    movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"]
)

# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request: Request, exc: RequestValidationError):
#     if request.method == "POST" and request.url.path == "accounts/reset-password/complete/":
#         return JSONResponse(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             content=jsonable_encoder({"detail": "Invalid email or token."}),
#     )
