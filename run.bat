@echo off
chcp 65001 >nul
title Şifreleme Uygulaması
color 0A

echo ========================================
echo   Şifreleme Uygulaması Başlatılıyor...
echo ========================================
echo.

REM Batch dosyasının bulunduğu dizine geç
pushd "%~dp0"

REM Mevcut dizini göster
echo Mevcut dizin: %CD%
echo.

REM app.py dosyasının varlığını kontrol et
if not exist "app.py" (
    echo [HATA] app.py dosyası bulunamadı!
    echo Mevcut dizin: %CD%
    echo Lütfen run.bat dosyasını proje klasöründe çalıştırın.
    pause
    popd
    exit /b 1
)

REM Python'un kurulu olup olmadığını kontrol et
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadı!
    echo Lütfen Python'u yükleyin ve PATH'e ekleyin.
    pause
    popd
    exit /b 1
)

echo Python bulundu: 
python --version
echo.

REM Gerekli kütüphanelerin kurulu olup olmadığını kontrol et
echo Gerekli kütüphaneler kontrol ediliyor...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [UYARI] Flask bulunamadı. Kütüphaneler yükleniyor...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [HATA] Kütüphaneler yüklenemedi!
        pause
        popd
        exit /b 1
    )
)

python -c "from Crypto.Cipher import AES" >nul 2>&1
if errorlevel 1 (
    echo [UYARI] PyCryptodome bulunamadı. Yükleniyor...
    python -m pip install pycryptodome
    if errorlevel 1 (
        echo [HATA] PyCryptodome yüklenemedi!
        pause
        popd
        exit /b 1
    )
)

echo Kütüphaneler hazır.
echo.
echo ========================================
echo   Uygulama başlatılıyor...
echo   Tarayıcınız otomatik olarak açılacak.
echo   Durdurmak için Ctrl+C tuşlarına basın.
echo ========================================
echo.

REM 2 saniye bekle ve tarayıcıyı aç
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000

REM Uygulamayı başlat
python app.py

REM Uygulama kapanınca
if errorlevel 1 (
    echo.
    echo [HATA] Uygulama bir hata ile kapandı!
    echo.
)

popd
pause

