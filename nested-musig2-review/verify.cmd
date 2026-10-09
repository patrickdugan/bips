@echo off
rem Runs verify.sh through Git Bash. Set PYTHON if python3 is not on PATH.
set "BASH=C:\Program Files\Git\bin\bash.exe"
if not exist "%BASH%" set "BASH=C:\Program Files\Git\usr\bin\bash.exe"
if not exist "%BASH%" (
  echo Git Bash not found; run verify.sh from a POSIX shell.
  exit /b 1
)
if "%PYTHON%"=="" set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
"%BASH%" -c "cd \"$(cygpath -u '%~dp0')\" && PYTHON=\"$(cygpath -u '%PYTHON%')\" ./verify.sh"
