# API Reference

Base URL (Docker/dev): `http://localhost:8001`

## Authentication
All endpoints require authentication via httpOnly cookie (browser) or API key (header `X-API-Key`).

## Endpoints

See the interactive Swagger docs at: `http://localhost:8001/docs`

### Auth
- `POST /auth/register` — Register new user + organization
- `POST /auth/login` — Login (sets httpOnly cookie)
- `POST /auth/logout` — Logout (clears cookie)
- `GET /auth/me` — Get current user
- `POST /auth/forgot-password` — Request password reset
- `POST /auth/reset-password` — Reset password with token
- `POST /auth/rotate-password` — Rotate password when expired

### Profile
- `GET /users/me` — Get profile
- `PATCH /users/me/profile` — Update profile
- `POST /users/me/password` — Change password
- `GET /users/me/activities` — Recent activity
- `GET /users/me/notifications` — Notification prefs
- `PATCH /users/me/notifications` — Update notification prefs

### Orgs & Projects
- `GET /orgs` — List orgs
- `POST /orgs` — Create org
- `GET /orgs/{org_id}/projects` — List projects
- `POST /orgs/{org_id}/projects` — Create project

### Members & Invites
- `GET /orgs/{org_id}/members` — List members
- `POST /orgs/{org_id}/members` — Add existing user to org
- `PATCH /orgs/{org_id}/members/{member_id}` — Update member role
- `DELETE /orgs/{org_id}/members/{member_id}` — Remove member
- `GET /orgs/{org_id}/invites` — List invites
- `POST /orgs/{org_id}/invites` — Create invite
- `PATCH /orgs/{org_id}/invites/{invite_id}` — Disable/enable invite
- `GET /invites/{token}` — Get invite by token
- `POST /invites/{token}/accept` — Accept invite

### Users
- `GET /users?org_id=X` — List platform users (admin/owner only)

### Findings
- `GET /findings?project_id=X` — List findings
- `POST /findings/manual` — Create finding manually
- `PATCH /findings/{id}` — Update finding
- `DELETE /findings/{id}` — Delete finding

### Assets
- `GET /assets?project_id=X` — List assets
- `POST /assets` — Create asset
- `PATCH /assets/{id}` — Update asset
- `DELETE /assets/{id}` — Delete asset

### Scans
- `POST /scans/run` — Queue a scan
- `GET /scans?project_id=X` — List scans
- `GET /scans/{scan_id}/logs` — Scan logs

### VulnDB
- `GET /vulndb/search?q=...` — Search catalog
- `GET /vulndb/stats` — Catalog stats
- `POST /vulndb` — Create manual template
- `POST /vulndb/import` — Import JSONL file

### Import/Export
- `POST /import/bulk` — Bulk import findings + assets
- `GET /findings/export?project_id=X&format=csv` — Export findings

### Audit
- `GET /audit-logs` — Audit log (paginated)
