# Open API Exposure Scanner

A full-stack web application that scans domains for exposed API endpoints, sensitive files, and hidden URLs discovered from HTML/JavaScript files.

## 🚀 Quick Deploy to Netlify

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed step-by-step instructions.**

### Quick Steps:
1. Deploy Cloudflare Worker (get the URL)
2. Push code to GitHub
3. Connect GitHub repo to Netlify
4. Set `VITE_API_URL` environment variable in Netlify
5. Deploy!

## Features

- **Common API Endpoint Scanning**: Automatically checks 18+ common API endpoints
- **Homepage Crawling**: Extracts URLs from HTML and JavaScript files
- **Sensitive File Detection**: Identifies exposed configuration and sensitive files
- **Real-time Results**: Beautiful UI with collapsible result sections
- **Status Code Detection**: Shows HTTP status codes and identifies open endpoints

## Project Structure

```
.
├── frontend/          # React + Vite + TailwindCSS frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── DomainInput.jsx
│   │   │   ├── ResultCard.jsx
│   │   │   └── Loader.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   └── vite.config.js
├── worker/            # Cloudflare Worker backend
│   ├── index.js
│   ├── wrangler.toml
│   └── package.json
└── README.md
```

## Tech Stack

### Frontend
- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **TailwindCSS** - Styling

### Backend
- **Cloudflare Workers** - Serverless backend
- **Wrangler** - Cloudflare Workers CLI

## Deployment

### Backend (Cloudflare Worker)

```bash
cd worker
npm install
npm install -g wrangler
wrangler login
npm run deploy
```

**Copy the Worker URL** - you'll need it for the frontend!

### Frontend (Netlify)

1. **Push to GitHub** (this repository)
2. **Connect to Netlify**:
   - Go to [Netlify Dashboard](https://app.netlify.com)
   - Import from GitHub
   - Select this repository
   - Set build settings:
     - Base directory: `frontend`
     - Build command: `npm run build`
     - Publish directory: `frontend/dist`
3. **Set Environment Variable**:
   - Add `VITE_API_URL` = `https://your-worker-url.workers.dev`
4. **Deploy!**

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed instructions.

## API Endpoints

### POST /scan

Scans a domain for exposed APIs and sensitive files.

**Request:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "domain": "example.com",
  "common_endpoints": [
    {
      "url": "https://example.com/api/",
      "status": 200,
      "open": true,
      "sample": "{...}"
    }
  ],
  "discovered_endpoints": [
    {
      "url": "https://example.com/api/v1/products",
      "found_in": "homepage_html"
    }
  ],
  "sensitive_files": [
    {
      "url": "https://example.com/config.json",
      "status": 200,
      "exposed": true
    }
  ]
}
```

## Common Endpoints Scanned

- `/api/`
- `/api/v1/`
- `/api/users`
- `/api/auth`
- `/api/admin`
- `/api-docs`
- `/api/v1/auth`
- `/graphql`
- `/swagger.json`
- `/openapi.json`
- `/wp-json/`
- `/config.json`
- `/settings.json`
- `/env`
- `/.env`
- `/.git/HEAD`
- `/debug`
- `/phpinfo.php`

## Sensitive Files Checked

- `/.env`
- `/env`
- `/config.json`
- `/config.js`
- `/settings.json`
- `/.git/HEAD`
- `/phpinfo.php`

## Security & Ethics

⚠️ **Important**: This tool is for security testing purposes only. Only scan:
- Domains you own
- Domains you have explicit written permission to test
- Domains in authorized bug bounty programs

Unauthorized scanning may be illegal and unethical. Use responsibly.

## License

This project is provided as-is for educational and authorized security testing purposes.

---

**Built with ❤️ for security researchers and developers**
