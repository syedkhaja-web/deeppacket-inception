# Full clean push - nukes local .git and force-pushes everything fresh
param([string]$Token)
if (-not $Token) { $Token = Read-Host "Enter GitHub PAT" }
$remote = "https://${Token}@github.com/syedkhaja-web/deeppacket-inception.git"
$root   = "c:\Users\SYED TAQHI\Desktop\deeppacket   inception"

Set-Location -LiteralPath $root

# Remove old .git so we start perfectly clean
Write-Host "Cleaning old git history..." -ForegroundColor Yellow
Remove-Item -Recurse -Force ".git" -ErrorAction SilentlyContinue

# Fresh init on main branch
git init --initial-branch=main
git config user.email "deploy@dpi.local"
git config user.name  "DPI Deploy"

# Stage everything (gitignore will exclude secrets automatically)
git add .

git commit -m "full clean deploy: spring boot AI + java-dpi + github actions"

git remote add origin $remote

Write-Host "Pushing to GitHub..." -ForegroundColor Cyan
git push -u origin main --force

Write-Host ""
Write-Host "DONE! https://github.com/syedkhaja-web/deeppacket-inception" -ForegroundColor Green
Write-Host "GitHub Actions will now build and deploy to Railway automatically." -ForegroundColor Green
