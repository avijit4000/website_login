# FastAPI Authentication API

This service provides local email/password authentication and optional Google OAuth 2.0 login. Passwords are stored as Argon2 hashes, never as plain text. SQLite is used by default; set `DATABASE_URL` to use another SQLAlchemy-supported database.

## Run locally

```powershell
\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload
```

Open `http://localhost:8000/docs` for Swagger UI.

## Endpoints

- `POST /auth/register` with `{ "email": "you@example.com", "password": "at-least-8-chars" }`
- `POST /auth/login` with the same fields; returns a JWT bearer token
- `POST /auth/logout` with `Authorization: Bearer <token>`; revokes that token
- `GET /auth/me` with `Authorization: Bearer <token>`
- `GET /auth/google/login` to start Google login
- `POST /auth/forgot-password` with `{ "email": "you@example.com" }`
- `POST /auth/reset-password` with `{ "token": "...", "new_password": "..." }`

For local development, `DEBUG=true` includes the reset token in the forgot-password response. In production, send that token through an email provider instead and keep `DEBUG=false`.

For Google login, configure OAuth credentials in `.env` and register `http://localhost:8000/auth/google/callback` as an authorized redirect URI in Google Cloud Console. The callback returns the same JWT response as regular login.

Before production, use long random secrets, HTTPS, a production database, migrations, rate limiting, and an email provider for password-reset links.