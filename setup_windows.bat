@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
set "PYTHONUTF8=1"
cd /d "%~dp0"

echo.
echo [1/6] Procurando o Python...
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY ( where py >nul 2>&1 && set "PY=py" )
if not defined PY (
  echo   Python nao encontrado. Instale o Python 3.10+ e rode de novo.
  pause & exit /b 1
)
%PY% --version

echo.
echo [2/6] Memoria do Docker ^(.wslconfig^)...
set "RESTART_WSL=0"
if exist "%USERPROFILE%\.wslconfig" (
  echo   .wslconfig existente:
  type "%USERPROFILE%\.wslconfig"
) else (
  > "%USERPROFILE%\.wslconfig" echo [wsl2]
  >> "%USERPROFILE%\.wslconfig" echo memory=16GB
  >> "%USERPROFILE%\.wslconfig" echo processors=6
  echo   Criado %USERPROFILE%\.wslconfig com 16 GB e 6 processadores.
  set "RESTART_WSL=1"
)

if "!RESTART_WSL!"=="1" (
  echo   Reiniciando o WSL ^(o Docker Desktop vai fechar e reabrir^)...
  wsl --shutdown
  timeout /t 5 /nobreak >nul
)

docker info >nul 2>&1
if errorlevel 1 (
  echo   Abrindo o Docker Desktop...
  start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
)
echo   Aguardando o Docker responder ^(ate 3 minutos^)...
set /a TRIES=0
:waitdocker
docker info >nul 2>&1 && goto dockerok
set /a TRIES+=1
if !TRIES! geq 36 (
  echo   O Docker nao respondeu. Abra o Docker Desktop manualmente e rode de novo.
  pause & exit /b 1
)
timeout /t 5 /nobreak >nul
goto waitdocker
:dockerok
echo   Docker pronto.

echo.
echo [3/6] Gerando o .env...
%PY% tasks.py init

echo.
echo [4/6] Ajuste vm.max_map_count...
%PY% tasks.py sysctl

echo.
echo [5/6] Conferindo pre-requisitos ^(docs\evidencias\B01_check.txt^)...
%PY% tasks.py check > docs\evidencias\B01_check.txt 2>&1
type docs\evidencias\B01_check.txt

echo.
echo [6/6] Baixando imagens e o modelo do LLM ^(docs\evidencias\B01_pull.txt^)...
%PY% tasks.py pull > docs\evidencias\B01_pull.txt 2>&1
%PY% -c "lines=open(r'docs\evidencias\B01_pull.txt',encoding='utf-8',errors='replace').read().splitlines(); print('\n'.join(lines[-8:]))"

echo.
echo Concluido. Proximo passo: python tasks.py up
pause
