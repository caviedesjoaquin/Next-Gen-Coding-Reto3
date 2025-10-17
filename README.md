# Next-Gen Coding — Reto 3

Small project demonstrating a secure user authentication module with unit tests and some developer tooling (linters, security scans and an AI-specific code checker).

- Language: Python 3.11
- Main modules:
  - `auth_module/` — Authentication implementation (registration, login, JWT, role management).
  - `tests/` — Pytest suite that validates auth behavior and security checks.
  - `scripts/ai_code_checker.py` — Lightweight analyzer to flag AI-generation artifacts and risky patterns in Python code.

---

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Running tests](#running-tests)
- [Developer tooling / CI](#developer-tooling--ci)
- [Security considerations](#security-considerations)
- [Project structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- Secure password hashing using bcrypt.
- Password policy validation (length, character classes, no spaces, avoids email parts, common passwords).
- Account lockout after configurable failed attempts.
- JWT access token issuance and verification.
- Role management (basic `admin` / `user` roles).
- Unit tests covering registration, login, lockout, password rules, JWT verification, roles and some security checks.
- CI pipeline that runs tests, coverage, pylint and bandit.
- An optional script (`scripts/ai_code_checker.py`) to detect AI-generated code patterns like hardcoded secrets, weak crypto usage, SQL injection risks, TODO/HACK markers and commented-out code.

---

## Quick start

1. Clone the repository
   ```
   git clone https://github.com/caviedesjoaquin/Next-Gen-Coding-Reto3.git
   cd Next-Gen-Coding-Reto3
   ```

2. Create and activate a virtual environment (recommended)
   ```
   python -m venv .venv
   source .venv/bin/activate   # macOS / Linux
   .venv\Scripts\activate      # Windows
   ```

3. Install dependencies
   ```
   pip install -r requirements.txt
   ```

4. Environment variables
   - `JWT_SECRET` (optional) — secret used to sign tokens. If not set, `auth_module` uses a default of `testsecret` for tests and local development. For production, always set a strong secret:
     ```
     export JWT_SECRET="a-very-strong-secret"
     ```

5. Use the auth module programmatically
   - The module exposes:
     - `user_register(db, email, password, full_name)` -> creates a new user (returns User)
     - `user_login(db, email, password)` -> returns JWT string on success
     - `verify_jwt_token(token)` -> decodes and validates token
     - `assign_role(db, user_id, role_name)` -> add role
     - `get_user_roles(db, user_id)` -> list roles
     - `get_password_hash(password)` and `check_password(plain, hash)` for password handling
   - The functions expect a SQLAlchemy session (the tests show examples creating a temporary SQLite DB/session).

---

## Running tests

The repo includes a comprehensive pytest suite located in `tests/`. To run tests locally:

```
pytest tests/
```

Important test notes:
- Tests use a temporary SQLite database created per test module or function (see `tests/test_auth_module.py`).
- The test suite verifies password rules, duplicate emails, login behavior, account lockout, JWT creation/verification, role assignment and basic SQL injection protection checks.
- JWT tests use the `JWT_SECRET` environment variable if set; otherwise the default test secret is used.

To run tests + coverage (same as CI):

```
pytest tests/ --cov=src --cov-report=term --cov-report=xml
```

To enforce an overall coverage threshold locally (CI uses 80%):

```
pytest tests/ --cov=src --cov-fail-under=80
```

---

## Developer tooling / CI

A GitHub Actions workflow is included at `.github/workflows/ci.yml`. It runs on `push` and `pull_request` for `main` and `develop` branches and performs:

- Checkout
- Python setup (3.11)
- Install requirements
- Run tests with coverage and enforce coverage threshold
- Run `pylint` on `auth_module/`
- Run `bandit -r auth_module/` for security scanning
- Run any scripts (note: the workflow currently runs `python scripts/` — ensure script entrypoints if you adjust CI)

You can run the included AI code checker locally:

```
python scripts/ai_code_checker.py <file_or_directory>
```

It reports patterns like hardcoded secrets, weak cryptographic primitives and likely SQL injection usage. The script returns a non-zero exit code if any critical findings are present.

---

## Security considerations

- Passwords are hashed with bcrypt (see `auth_module/auth_module.py`).
- Strong password policy is enforced in `_validate_password`.
- Account lockout is implemented after a configurable number of failed attempts (defaults in the module).
- JWT tokens are signed with `JWT_SECRET`. Use a strong environment-secret in production.
- Avoid running the repo with default secrets in production.
- The repository contains an AI-specific code checker to help detect possible accidental leaks or weak constructs; use it to scan code before committing.

---

## Project structure

- auth_module/
  - auth_module.py — core authentication implementation, models and utilities
- tests/
  - test_auth_module.py — unit test suite for the auth module
- scripts/
  - ai_code_checker.py — AI artifact and risk pattern scanner
- .github/workflows/ci.yml — CI pipeline configuration
- requirements.txt — Python dependencies (used by CI and local development)

---

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repo
2. Create a feature branch from `develop` or `main`
3. Run tests and linters locally
4. Open a PR with a clear description of changes

Please follow secure coding practices and add tests for new logic.

---

## License

Specify your license here (e.g., MIT). If none is present in the repo, add one before publishing.
