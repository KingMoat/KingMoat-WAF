@echo off
rem Build the KingMoat console frontend (node dislikes UNC cwd).
cd /d "%~dp0"
if not exist node_modules (
  echo == npm install
  call npm install --registry=https://registry.npmmirror.com --no-audit --no-fund || exit /b 1
)
echo == vite build
call npm run build || exit /b 1
