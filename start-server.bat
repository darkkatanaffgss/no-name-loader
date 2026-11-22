@echo off
title no name — License API Server
cd /d "%~dp0"
if not exist node_modules call npm install
node api-server\server.js
pause
