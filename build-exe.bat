@echo off
title no name — Release Builder
cd /d "%~dp0"
if not exist node_modules call npm install
call npm run build
pause
