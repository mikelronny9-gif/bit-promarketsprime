# Bit-Promarketsprime Trade — Demo Starter

This is a **demo-only** broker/trading dashboard starter. Balances and transaction requests are simulated. It is not connected to payment rails, real trading, real investment accounts, or a real identity-verification provider.

## Project structure

- `public/index.html`, `public/styles.css`, `public/app.js`: browser interface
- `server.js`: Express backend and API
- `create-admin.js`: create the first admin account
- `render.yaml`: Render deployment blueprint

## Run locally

1. Install Node.js 20 or later.
2. Run `npm install`.
3. Set a long random `SESSION_SECRET` environment variable.
4. Run `npm start`.
5. Open `http://localhost:3000`.

## Create an admin

Run this on your server/Render Shell, not in GitHub and not in the browser:

`node create-admin.js "Platform Admin" "your-admin-email@example.com" "Use-A-Unique-Password-At-Least-16-Chars"`

Use a unique password of at least 16 characters. Do not commit passwords or `.env` files to GitHub.

## Deploy to Render

1. Upload the contents of this ZIP to a GitHub repository, preserving the `public` folder.
2. In Render, create a new Blueprint and connect the repository.
3. Review the service and persistent-disk plan/pricing before deploying.
4. After deployment, create your admin using Render Shell if available on your plan.
5. Test `/api/health`, registration, login, and admin functions.

## Security and production limits

Before handling real customer funds or identity data, this starter requires a professional security review, compliance review, hardened account recovery and MFA, CSRF protections, operational monitoring, backup/restore testing, and vetted regulated payment/trading/KYC providers. Do not use demo controls to represent real verification or real money movement.
