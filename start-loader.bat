@echo off
title no name — Loader
cd /d "%~dp0"
if not exist node_modules call npm install
call npm start
