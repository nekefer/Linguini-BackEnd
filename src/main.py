from fastapi import FastAPI
from .database.core import engine, Base
from .api import register_routes
from .logging import configure_logging
from .config import get_settings
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .middleware.security import SecurityHeadersMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

settings = get_settings()

configure_logging(settings.log_level)

app = FastAPI(docs_url=None, redoc_url=None)

# Add security headers middleware FIRST (highest priority)
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key  # ✅ Use separate session secret key
)

# Configure CORS - SECURE VERSION
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # Use CORS origins from settings
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # ✅ Only allow necessary HTTP methods
    allow_headers=["Authorization", "Content-Type", "Accept"],  # ✅ Only allow necessary headers
    expose_headers=["X-Total-Count"],  # ✅ Only expose headers that frontend needs
)

# Only create tables in development environment
if settings.is_development:
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully (development mode)")

# Serve Swagger UI assets locally
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )

register_routes(app)