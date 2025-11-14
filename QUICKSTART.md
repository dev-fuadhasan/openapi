# Quick Start Guide

Get the Open API Exposure Scanner up and running in 5 minutes!

## Step 1: Deploy Backend (Cloudflare Worker)

```bash
cd worker
npm install
npm install -g wrangler
wrangler login
npm run deploy
```

**Copy the worker URL** from the deployment output (e.g., `https://open-api-exposure-scanner.xxxxx.workers.dev`)

## Step 2: Configure Frontend

```bash
cd frontend
npm install
```

Create `.env` file:
```env
VITE_API_URL=https://your-worker-url.workers.dev
```

## Step 3: Test Locally

```bash
# In frontend directory
npm run dev
```

Visit `http://localhost:5173` and test with a domain!

## Step 4: Deploy Frontend

### Option A: Vercel (Recommended)

```bash
npm install -g vercel
cd frontend
vercel
```

Set environment variable `VITE_API_URL` in Vercel dashboard.

### Option B: Netlify

```bash
npm install -g netlify-cli
cd frontend
netlify deploy --prod
```

Set environment variable `VITE_API_URL` in Netlify dashboard.

## That's it! 🎉

Your scanner is now live and ready to use.

## Testing

Try scanning:
- `example.com` (safe test domain)
- Your own domain
- Any domain you have permission to test

**Remember**: Only scan domains you own or have permission to test!

