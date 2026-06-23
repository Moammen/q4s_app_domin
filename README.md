# Q4S Connect App

## First Time Setup

**1. Build & start the monitoring app**
```cmd
cd q4s_site_monitoring
docker compose up -d --build
```
→ Runs on http://127.0.0.1:1887 | Admin: `admin` / `123456789`

**2. Build & start the main app**
```cmd
cd ..\q4s_connect
docker compose up -d --build
```
→ Runs on http://127.0.0.1:8000

**3. Run the seed**
```cmd
cd q4s_connect
docker compose exec web python manage.py seed
```
Takes 1–2 minutes. Creates 10 Dubai sites with 10 months of data (~110,000 rows).

---

## Every Day

```cmd
cd q4s_site_monitoring
docker compose up -d

cd ..\q4s_connect
docker compose up -d
```

## Stop

```cmd
cd q4s_connect && docker compose down
cd ..\q4s_site_monitoring && docker compose down
```

---


## Run the Seed Again

Safe to run anytime — it clears old data and starts fresh. No duplicates.

```cmd
cd q4s_connect
docker compose exec web python manage.py seed
```

---


## Users (after seed)

| Username | Password | Role |
|---|---|---|
| `admin_dxb` | `Admin@2026` | Admin |
| `manager_dxb` | `Manager@2026` | Admin |
| `engineer1` | `Engineer@2026` | Engineer |
| `operator1` | `Operator@2026` | Operator |
