@echo off
chcp 936 >nul 2>&1
setlocal
title 多平台账号看板 - WorkBuddy / MiniMax / DuMate
cd /d "%~dp0src"

if not exist "server.py" (
    echo [错误] 未找到 src\server.py
    echo        请把本文件放在 dashboard_analysis 目录下，与 src 文件夹同级。
    echo.
    pause
    exit /b 1
)

set "PORT=8799"

rem 带 --no-open 参数时只启动服务，不自动打开浏览器
set "OPEN=1"
if /i "%~1"=="--no-open" set "OPEN=0"

rem ================= 1) 服务是否已经在运行 =================
netstat -ano | findstr /c:":%PORT% " | findstr /i "LISTENING" >nul 2>&1
if not errorlevel 1 (
    curl -s -m 3 http://127.0.0.1:%PORT%/api/ping 2>nul | findstr /c:"ok" >nul 2>&1
    if not errorlevel 1 (
        echo [提示] 看板服务已经在运行，直接打开页面：
        echo        http://127.0.0.1:%PORT%
        if "%OPEN%"=="1" start "" "http://127.0.0.1:%PORT%"
        %SystemRoot%\System32\timeout.exe /t 2 /nobreak >nul 2>&1
        exit /b 0
    )
    echo [错误] 端口 %PORT% 已被其他程序占用，看板无法启动。
    echo        请关闭占用该端口的程序后重试，或修改本文件中的 PORT 值。
    echo.
    pause
    exit /b 1
)

rem ================= 2) 查找一个带 requests 的 Python =================
set "PY="

call :try python
if not errorlevel 1 ( set PY="python" & goto :found )

call :try "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
if not errorlevel 1 ( set PY="%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" & goto :found )

call :try "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not errorlevel 1 ( set PY="%LOCALAPPDATA%\Programs\Python\Python314\python.exe" & goto :found )

call :try "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not errorlevel 1 ( set PY="%LOCALAPPDATA%\Programs\Python\Python313\python.exe" & goto :found )

call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not errorlevel 1 ( set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe" & goto :found )

call :try "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not errorlevel 1 ( set PY="%LOCALAPPDATA%\Programs\Python\Python311\python.exe" & goto :found )

call :try "C:\Python314\python.exe"
if not errorlevel 1 ( set PY="C:\Python314\python.exe" & goto :found )

call :try "C:\Python313\python.exe"
if not errorlevel 1 ( set PY="C:\Python313\python.exe" & goto :found )

call :try "C:\Python312\python.exe"
if not errorlevel 1 ( set PY="C:\Python312\python.exe" & goto :found )

py -3 -c "import requests" >nul 2>&1
if not errorlevel 1 ( set PY=py -3 & goto :found )

echo [错误] 没有找到可用的 Python。本看板需要 Python 3.9 以上，并装好 requests 库。
echo.
echo        解决办法：
echo        1. 安装 Python，安装时勾选 Add Python to PATH
echo        2. 打开命令提示符执行： pip install requests
echo.
pause
exit /b 1

rem ================= 3) 启动服务并自动打开浏览器 =================
:found
echo [就绪] 使用解释器： %PY%
echo.
echo ============================================================
echo                 多平台账号看板 · 本地服务
echo.
echo    访问地址： http://127.0.0.1:%PORT%
echo    停止服务： 关闭本窗口，或按 Ctrl+C
echo ============================================================
echo.

if "%OPEN%"=="1" (
    start "" /min powershell -NoProfile -WindowStyle Hidden -Command "for($i=0;$i -lt 60;$i++){try{Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 -Uri 'http://127.0.0.1:%PORT%/api/ping' | Out-Null; Start-Process 'http://127.0.0.1:%PORT%'; break}catch{Start-Sleep -Milliseconds 500}}"
)

%PY% server.py

echo.
echo 服务已停止。
pause
exit /b 0

rem ================= 探测子过程：能否 import requests =================
:try
"%~1" -c "import requests" >nul 2>&1
exit /b %errorlevel%
