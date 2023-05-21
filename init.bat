@echo off
set "REPO_URL=https://github.com/BUR-Ak-47/vscan.git"
set "REPO_DIR=vscan"
set "REQUIREMENTS_FILE=requirements.txt"

echo Cloning repository...
git clone %REPO_URL% %REPO_DIR%

echo Installing requirements...
cd %REPO_DIR%
pip install -r %REQUIREMENTS_FILE%

echo Cleanup...
cd ..
rd /s /q %REPO_DIR%

echo Done.
