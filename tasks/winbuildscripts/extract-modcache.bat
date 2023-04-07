if exist c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz (
    @echo Extracting modcache
    @echo Starting tar.gz -> tar extract: %date% %time%
    Powershell -C "7z x c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz -oc:\dev\go\src\github.com\DataDog\datadog-agent"
    @echo Starting tar -> modcache extract: %date% %time%
    Powershell -C "7z x c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar -oc:\modcache"
    @echo Finished tar.gz -> tar extract: %date% %time%
    del /f c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar.gz
    del /f c:\dev\go\src\github.com\DataDog\datadog-agent\modcache.tar
    @echo Modcache extracted: %date% %time%
) else (
    @echo modcache.tar.gz not found, dependencies will be downloaded
)
