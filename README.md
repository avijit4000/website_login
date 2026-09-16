# FastAPI Authentication API

This service provides local email/password authentication and optional Google OAuth 2.0 login. Passwords are stored as Argon2 hashes, never as plain text. SQLite is used by default; set `DATABASE_URL` to use another SQLAlchemy-supported database.

## Run locally

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload
```

Open `http://localhost:8000/docs` for Swagger UI.

## Environment configuration

Set these values in `.env`:

```env
DATABASE_URL=sqlite:///./auth.db
SECRET_KEY=replace-with-a-long-random-secret
SESSION_SECRET=replace-with-another-long-random-secret
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
```

For Google login, create a Web application OAuth client in Google Cloud Console and add this authorized redirect URI:

```text
http://localhost:8000/auth/google/callback
```

Start Google login at `http://localhost:8000/auth/google/login`. The callback creates or finds the local user and returns a JWT bearer token.

## Endpoints

- `POST /auth/register` with `{ "email": "you@example.com", "password": "at-least-8-chars" }`
- `POST /auth/login` with the same fields; returns a JWT bearer token
- `POST /auth/logout` with `Authorization: Bearer <token>`; revokes that token
- `GET /auth/me` with `Authorization: Bearer <token>`
- `GET /auth/google/login` to start Google login
- `GET /auth/google/callback` to complete Google login
- `POST /auth/forgot-password` with `{ "email": "you@example.com" }`
- `POST /auth/reset-password` with `{ "token": "...", "new_password": "..." }`

For local development, `DEBUG=true` includes the reset token in the forgot-password response. In production, send that token through an email provider instead and keep `DEBUG=false`.

Before production, use long random secrets, HTTPS, a production database, migrations, rate limiting, and an email provider for password-reset links.


## Run
.\.venv\Scripts\python.exe .\googlelogin.py

http://localhost:5000/auth

http://localhost:5000
