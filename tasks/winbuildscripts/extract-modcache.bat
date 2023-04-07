if exist c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz (
    @echo Extracting modcache
    Powershell -C "7z x c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz -oc:\dev\go\src\github.com\DataDog\datadog-agent"
    Powershell -C "7z x c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar -oc:\modcache"
    del /f c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz
    del /f c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar
    @echo Modcache extracted
) else (
    @echo modcache.tar.gz not found, dependencies will be downloaded
)
