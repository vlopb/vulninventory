# Deployment Guide

## Docker (Recommended)

```bash
git clone https://github.com/CrisorHacker/vulninventory.git
cd vulninventory
cp .env.example .env
# Edit .env — set JWT_SECRET, COOKIE_SECURE=true, DEV_MODE=false
docker compose up -d
```

Services (default):
- UI: `http://localhost:5173`
- API: `http://localhost:8001`

## Production Checklist

- [ ] Set strong `JWT_SECRET` (min 32 chars)
- [ ] Set `COOKIE_SECURE=true`
- [ ] Set `DEV_MODE=false`
- [ ] Set `REGISTRATION_ENABLED=false` (after creating admin)
- [ ] Set `CORS_ORIGINS` to your domain only
- [ ] Set `COOKIE_DOMAIN` to your domain
- [ ] Use HTTPS (reverse proxy: Caddy, Nginx, or Traefik)
- [ ] Backup PostgreSQL regularly
- [ ] Change default DB password
