@echo off
chcp 65001 >nul
cd /d "%~dp0"

REM Windows Store 별칭 때문에 "python" 명령이 동작하지 않을 수 있음
set "PYTHON="
where py >nul 2>&1 && set "PYTHON=py"
if not defined PYTHON if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Python\bin\python.exe"
)
if not defined PYTHON (
    echo Python을 찾을 수 없습니다.
    echo https://www.python.org/downloads/ 에서 Python을 설치하세요.
    echo 설치 시 "Add Python to PATH" 옵션을 체크하세요.
    pause
    exit /b 1
)

echo ============================================================
echo  MalwareGuard 실행 스크립트
echo ============================================================
echo 사용 중인 Python:
%PYTHON% --version
echo.

echo [1단계] 패키지 설치 중...
%PYTHON% -m pip install -r requirements.txt
if errorlevel 1 goto error

echo.
echo [2단계] AI 모델 학습 중... (수 분 소요)
%PYTHON% train.py
if errorlevel 1 goto error

echo.
echo [3단계] 웹 서버 시작...
echo  브라우저에서 http://localhost:5000 으로 접속하세요.
echo.
%PYTHON% app.py
goto end

:error
echo.
echo 오류가 발생했습니다. 위 메시지를 확인하세요.
pause
exit /b 1

:end
pause
