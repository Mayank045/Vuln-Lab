# VulnLab

VulnLab is an intentionally vulnerable password-manager application for local
and authorized web-security training. It preserves the original React/Vite,
Express, and MongoDB stack while pairing vulnerable lab routes with secure
comparison routes.

> **Authorized-use disclaimer:** This application is intentionally vulnerable
> and is designed for educational and authorized security testing only. Run it
> locally or in an environment you own or have explicit permission to test.
> Use synthetic credentials and demo data only.

## Project goals

VulnLab is designed around a repeatable training workflow:

1. Observe the vulnerable implementation.
2. Test only the local or explicitly authorized instance.
3. Read the vulnerability explanation.
4. Compare the secure remediation.
5. Retest the secure behavior.

The original password-manager interface and root CRUD API remain available for
compatibility. The isolated `/api/lab/*` routes are the comparison surface.

## Technology stack

- React 18 and Vite
- Tailwind CSS
- Node.js and Express
- MongoDB
- MongoDB Node.js driver

## Architecture

```text
Browser
  └── React/Vite frontend
        └── Existing password-manager CRUD calls
              └── Express API on localhost:3000
                    └── MongoDB database and passwords collection
```

The backend currently keeps the original root routes and adds isolated lab
routes in `backend/server.js`. Lab ownership is simulated with the
`X-VulnLab-User` header and is not a production authentication mechanism.

## Project structure

```text
src/                  React frontend and password-manager UI
src/components/       Navbar, manager, and footer components
backend/server.js     Express API, MongoDB access, and lab routes
backend/.env          Local MongoDB configuration; do not commit secrets
docs/vulnerabilities/ Per-lab explanations and remediation guidance
public/               Static icons and frontend assets
```

## Installation and local setup

1. Install Node.js and MongoDB locally.
2. Start the local MongoDB service.
3. Configure `backend/.env` with a local database:

   ```text
   MONGO_URI=mongodb://localhost:27017
   DB_NAME=passop
   ```

4. Install frontend dependencies:

   ```powershell
   npm install
   ```

5. Install backend dependencies:

   ```powershell
   Set-Location backend
   npm install
   ```

6. Start the API in the backend directory:

   ```powershell
   node server.js
   ```

7. Start the frontend from the project root in a second terminal:

   ```powershell
   npm run dev
   ```

The API listens on `http://localhost:3000`. Vite prints the local frontend
URL in its terminal output.

## Vulnerability labs

| Lab | Vulnerable comparison | Secure comparison | Documentation |
|---|---|---|---|
| IDOR / BOLA | `/api/lab/vulnerable/passwords/:id` | `/api/lab/secure/passwords/:id` | [idor.md](docs/vulnerabilities/idor.md) |
| Broken access control | Vulnerable record mutations | Ownership-scoped mutations | [broken-access-control.md](docs/vulnerabilities/broken-access-control.md) |
| NoSQL injection | `/api/lab/vulnerable/search` | `/api/lab/secure/search` | [nosql-injection.md](docs/vulnerabilities/nosql-injection.md) |
| Stored XSS | Unsafe notes preview | React escaped notes preview | [stored-xss.md](docs/vulnerabilities/stored-xss.md) |
| Reflected XSS | Unsafe `q` preview | React escaped `q` preview | [reflected-xss.md](docs/vulnerabilities/reflected-xss.md) |
| Sensitive data exposure | `/api/lab/vulnerable/export` | `/api/lab/secure/export` | [sensitive-data-exposure.md](docs/vulnerabilities/sensitive-data-exposure.md) |
| Weak authentication | Unlimited vulnerable login | Rate-limited secure login | [authentication.md](docs/vulnerabilities/authentication.md) |
| Input validation | `/api/lab/vulnerable/records` | `/api/lab/secure/records` | [input-validation.md](docs/vulnerabilities/input-validation.md) |
| Security headers | Vulnerable diagnostics | Secure headers and diagnostics | [security-headers.md](docs/vulnerabilities/security-headers.md) |
| API security | Arbitrary cross-user update | Scoped allowlisted update | [api-security.md](docs/vulnerabilities/api-security.md) |

All lab credentials, records, and identities are synthetic. The training
header and in-memory tokens exist only to make local comparisons repeatable.

## Existing compatibility API

The original frontend continues to use:

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Read password records |
| POST | `/` | Create a password record |
| DELETE | `/` | Delete a password record |

These original routes intentionally remain unchanged during the incremental
transformation. They are not a secure production password-management API.

## Validation and testing

Run the available project checks from the root:

```powershell
npm run build
npm run lint
```

Run backend syntax validation:

```powershell
node --check backend/server.js
```

For security testing, use browser developer tools, Burp Suite, FFUF, Nmap, or
Nuclei only against the local VulnLab instance or another explicitly
authorized environment. Do not test third-party systems, production services,
real credentials, or real customer data.

## Secure remediation principles

- Derive identity from verified authentication rather than client headers.
- Enforce ownership and role authorization on every object operation.
- Validate and allowlist all server-side input.
- Project responses to the minimum required fields.
- Escape untrusted output in its rendering context.
- Rate-limit authentication and monitor repeated failures.
- Set security headers centrally and avoid framework fingerprinting.
- Keep detailed diagnostics in protected server-side logs.
- Never commit `.env` files containing secrets.

## Project status

Completed and runtime-verified phases:

- Rebranding and authorized-use disclaimer
- IDOR and broken access control
- NoSQL injection
- Stored and reflected XSS
- Sensitive data exposure
- Weak authentication controls
- Insecure input validation
- Security headers and information disclosure
- API security review

Documentation and final regression validation remain ongoing as the project
continues to evolve.
