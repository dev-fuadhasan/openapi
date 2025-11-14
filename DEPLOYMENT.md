# Deployment Guide for Netlify

## Prerequisites

1. **Cloudflare Account** (free tier works)
2. **GitHub Account**
3. **Netlify Account** (free tier works)

## Step 1: Deploy Cloudflare Worker (Backend)

**You need to do this FIRST before deploying the frontend!**

1. Install Wrangler CLI:
   ```bash
   npm install -g wrangler
   ```

2. Login to Cloudflare:
   ```bash
   wrangler login
   ```

3. Navigate to worker directory:
   ```bash
   cd worker
   npm install
   ```

4. Deploy the worker:
   ```bash
   npm run deploy
   ```

5. **Copy the Worker URL** from the output (e.g., `https://open-api-exposure-scanner.xxxxx.workers.dev`)

   **You'll need this URL for Step 3!**

## Step 2: Push Code to GitHub

1. Initialize git (if not already done):
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Open API Exposure Scanner"
   ```

2. Add your GitHub repository:
   ```bash
   git remote add origin https://github.com/dev-fuadhasan/openapi.git
   git branch -M main
   git push -u origin main
   ```

## Step 3: Deploy Frontend to Netlify

### Option A: Using Netlify Dashboard (Recommended)

1. Go to [Netlify](https://app.netlify.com) and sign in
2. Click **"Add new site"** → **"Import an existing project"**
3. Connect to **GitHub** and select your repository: `dev-fuadhasan/openapi`
4. Configure build settings:
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `frontend/dist`
5. Click **"Show advanced"** and add environment variable:
   - **Key**: `VITE_API_URL`
   - **Value**: `https://your-worker-url.workers.dev` (from Step 1)
6. Click **"Deploy site"**

### Option B: Using Netlify CLI

1. Install Netlify CLI:
   ```bash
   npm install -g netlify-cli
   ```

2. Navigate to frontend directory:
   ```bash
   cd frontend
   ```

3. Login to Netlify:
   ```bash
   netlify login
   ```

4. Deploy:
   ```bash
   netlify deploy --prod --dir=dist
   ```

5. Set environment variable in Netlify Dashboard:
   - Go to Site settings → Environment variables
   - Add `VITE_API_URL` with your worker URL
   - Redeploy

## Step 4: Verify Deployment

1. Visit your Netlify site URL
2. Try scanning a domain (e.g., `example.com`)
3. Check that results appear correctly

## Troubleshooting

### Frontend can't connect to backend
- Verify `VITE_API_URL` is set correctly in Netlify
- Check that the Cloudflare Worker is deployed and accessible
- Redeploy Netlify site after setting environment variable

### Build fails on Netlify
- Ensure base directory is set to `frontend`
- Check that build command is `npm run build`
- Verify publish directory is `frontend/dist`

### Worker deployment fails
- Make sure you're logged in: `wrangler login`
- Check that `wrangler.toml` is in the worker directory
- Verify Node.js 18+ is installed

## Important Notes

- The Cloudflare Worker must be deployed BEFORE the frontend
- The `VITE_API_URL` environment variable is required for the frontend to work
- After setting environment variables in Netlify, you may need to trigger a new deployment

