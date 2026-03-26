# Basic Auth

A **simple** HTTP server written in Go that demonstrates a basic authentication flow.

## It covers

- Password hashing with bcrypt
- Session management via secure cookies on SQLite
- Role-based access control (admin and regular users)
- Dev and prod environment separation

## Setup

```bash
go mod tidy
```

## Running

Development:

```bash
go run .
```

Production:

```bash
APP_ENV=prod DB_PATH=/var/lib/auth/auth.db ./basic-auth
```
