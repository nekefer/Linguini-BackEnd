from fastapi import FastAPI
from src.auth.controller import router as auth_router
# from src.users.controller import router as users_router
from src.youtube.controller import router as youtube_router
from src.vocabulary.controller import router as vocabulary_router

def register_routes(app: FastAPI):
    app.include_router(auth_router)
    # app.include_router(users_router)
    app.include_router(youtube_router)
    app.include_router(vocabulary_router)