# Backend API

This is the backend API service built with FastAPI.

## Dependencies

- FastAPI
- SQLModel
- Passlib
- Python-jose
- Pydantic
- Uvicorn

See `pyproject.toml` and `requirements.txt` for a complete list of dependencies.

## Configuration

The application uses environment variables for configuration.  See `core/config.py` for details.  A `.env` file at the root of the project is expected.

## API Endpoints

The API provides endpoints for:

- User management (creation, authentication, etc.) Look in `src/UserManagement/api.py` and `routers/user_auth.py` for specifics.
- User roles and permissions (`src/core/security/permissions.py`).

## Models

User and UserCredential models are defined in `src/UserManagement/models.py` and `models.py`.

## Authentication

Authentication is handled via JWT tokens.  See `src/core/security/auth.py` for implementation details.