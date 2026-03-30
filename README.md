# Login

Hosted login frontend for Continental ID, made by Continental.

## What it is

This repo contains the standalone authentication pages used by Continental products. It is made by Continental and provides the login, registration, and email verification UI that other apps can open in a popup or redirect flow.

## Main files

- `index.html`: small redirect page that forwards to `popup.html`
- `popup.html`: main login/register interface
- `verify.html`: email verification page
- `CNAME`: custom domain configuration for `login.continental-hub.com`
- `Old login/` and `idk/`: older retained copies of the auth pages

## Behavior

- Supports both login and registration in the same UI
- Talks to the Continental auth backend at `/api/auth`
- Accepts query parameters for trusted origin, redirect target, and API base URL
- Includes trusted-origin checks so the popup only redirects or posts back to approved app origins
- Handles email verification from tokenized links through `verify.html`

## Expected integrations

This frontend is designed to work with the Continental account system used by:

- Dashboard
- Grimoire
- other Continental web apps that rely on Continental ID

## Local development

This is a static frontend, so you can serve it locally with any static file server:

```bash
npx serve .
```

When running locally, the pages default to `http://localhost:5000` for the auth API.

## Notes

- This repo is frontend-only; the actual auth/session logic lives in the Continental Dashboard backend.
- The main production host is `login.continental-hub.com`.
