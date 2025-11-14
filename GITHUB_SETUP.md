# GitHub Setup Instructions

## Push Code to GitHub Repository

Follow these steps to push your code to `https://github.com/dev-fuadhasan/openapi`:

### Step 1: Initialize Git (if not already done)

```bash
git init
```

### Step 2: Add All Files

```bash
git add .
```

### Step 3: Create Initial Commit

```bash
git commit -m "Initial commit: Open API Exposure Scanner"
```

### Step 4: Add Remote Repository

```bash
git remote add origin https://github.com/dev-fuadhasan/openapi.git
```

If you get an error that remote already exists, use:
```bash
git remote set-url origin https://github.com/dev-fuadhasan/openapi.git
```

### Step 5: Push to GitHub

```bash
git branch -M main
git push -u origin main
```

If you get authentication errors, you may need to:
- Use a Personal Access Token instead of password
- Or use SSH: `git remote set-url origin git@github.com:dev-fuadhasan/openapi.git`

## After Pushing

1. Verify files are on GitHub
2. Follow [DEPLOYMENT.md](./DEPLOYMENT.md) to deploy to Netlify

