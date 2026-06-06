# ThreatLookup App

ThreatLookup App is a beginner-friendly full-stack web app that checks one input value against multiple OSINT and security data sources.

You can enter:

- An IP address
- A domain or hostname
- A full URL

The backend detects the input type, calls multiple sources, and returns one combined JSON response to the React frontend.

## Tech stack

- Backend: Django + Django REST Framework
- Frontend: React + Vite
- Database: SQLite

## Included data sources

- VirusTotal
- AbuseIPDB
- URLHaus
- ThreatFox
- Shodan InternetDB
- GreyNoise Community
- IP-API
- ipapi.is
- crt.sh
- Google DNS over HTTPS
- RDAP

## Project structure

- `backend/` contains the Django API
- `frontend/` contains the React app

## Before you start

You need these installed on Windows:

- Python 3
- Node.js
- VS Code

## Step-by-step setup for Windows in VS Code

### 1. Open the project

Open the folder `threatlookup-app` in VS Code.

### 2. Create the backend `.env` file

Inside the `backend` folder:

1. Copy `.env.example`
2. Rename the copy to `.env`
3. Add your real API keys

Example:

```env
DJANGO_SECRET_KEY=replace-this-with-your-own-secret-key
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
GREYNOISE_API_KEY=optional_greynoise_api_key_here
THREATFOX_AUTH_KEY=optional_threatfox_auth_key_here
```

If a key is missing, the app will skip that source and show a friendly message instead of crashing.

### 3. Start the backend

Open a VS Code terminal and run:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

The backend should now run at:

`http://127.0.0.1:8000`

### 4. Start the frontend

Open a second VS Code terminal and run:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

The frontend should now run at:

`http://localhost:5173`

## How to use the app

1. Open `http://localhost:5173`
2. Enter an IP, domain, or URL
3. Click `Run Lookup`
4. Read the summary and the result cards

Each card shows:

- Whether the source succeeded, failed, or was skipped
- A short message
- The raw JSON or raw API response

## API endpoint

The backend exposes one main endpoint:

```http
POST /api/lookup/
```

Example request body:

```json
{
  "value": "8.8.8.8"
}
```

## Notes for beginners

- API keys are never hardcoded in the source code
- Some sources only work for certain input types
- VirusTotal and AbuseIPDB require API keys
- GreyNoise Community can work without a key, but the rate limit is small unless you use an account key
- URLHaus is used only for URL lookups
- ThreatFox can search IPs, domains, and URLs with an abuse.ch Auth-Key
- Shodan InternetDB is used only for IP lookups
- GreyNoise Community is used only for IP lookups
- IP-API is used only for IP lookups and helps flag proxy / hosting usage
- ipapi.is is used only for IP lookups and helps flag VPN / proxy / datacenter usage
- crt.sh and Google DNS are used for domain-style lookups
- RDAP works for both IPs and domains / URL hostnames

## Useful commands

### Backend

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python manage.py test
python manage.py runserver
```

### Frontend

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
npm.cmd run build
```

## Troubleshooting

### PowerShell says `npm` scripts are disabled

Use `npm.cmd` instead of `npm`.

### The frontend cannot talk to the backend

Make sure:

- The Django server is running on port `8000`
- The React app is running on port `5173`
- `CORS_ALLOWED_ORIGINS` includes both `http://localhost:5173` and `http://127.0.0.1:5173`

### Some cards say skipped

That is expected when:

- The source only supports a different input type
- An API key is missing
- The third-party API is temporarily unavailable
