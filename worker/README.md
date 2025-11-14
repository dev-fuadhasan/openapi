# Worker - Open API Exposure Scanner Backend

Cloudflare Worker that handles API scanning logic.

## Deploy

```bash
npm install
npm install -g wrangler
wrangler login
npm run deploy
```

After deployment, copy the Worker URL and use it as `VITE_API_URL` in the frontend.

