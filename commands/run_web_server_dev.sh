#!/bin/sh

# Run web server
uvicorn main:app --host 0.0.0.0 --port 8080 --reload --reload-dir /usr/src/fastapi
