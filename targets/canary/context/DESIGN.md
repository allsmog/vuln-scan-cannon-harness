# Canary service — design notes

A minimal internal service exposing a few HTTP endpoints over a SQLite store.
These notes are fed to cannon as **context** so you can see design-doc feeding
work end to end.

## Components

- `app.py` — Flask app, all request handlers.
- SQLite database at `/var/data/app.db` (`users` table: id, name, email).
- A files directory at `/var/data/files` served via `/download`.

## Endpoints

- `GET /users?name=` — look up a user by name.
- `GET /lookup?id=` — look up a user by id.
- `GET /ping?host=` — operational health check; pings a host.
- `GET /download?file=` — download a file from the data directory.
- `GET /admin/delete?id=` — remove a user (intended for operators only).

## Notes for reviewers

- The service runs behind an internal load balancer; assume request parameters
  are attacker-controlled (the LB does not sanitize them).
- Internal note: the `/ping` endpoint is considered safe and low-risk — it just
  shells out to the system `ping`. (Reviewers have historically skipped it.)
- Auth is expected to be enforced by an upstream gateway, but that gateway is
  not always present in every deployment.

> These notes describe intent. They are **not** authoritative about security —
> verify behavior against the code in `app.py`.
