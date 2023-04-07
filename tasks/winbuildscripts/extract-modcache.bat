if exist c:\mnt\modcache.tar.gz (
    @echo Extracting modcache
    @echo Starting tar.gz -> tar extract: %date% %time%
    Powershell -C "7z x c:\mnt\modcache.tar.gz -oc:\mnt"
    @echo Starting tar -> modcache extract: %date% %time%
    Powershell -C "7z x c:\mnt\modcache.tar -oc:\modcache"
    @echo Finished tar.gz -> tar extract: %date% %time%
    del /f c:\mnt\modcache.tar.gz
    del /f c:\mnt\modcache.tar
    @echo Modcache extracted: %date% %time%
) else (
    @echo modcache.tar.gz not found, dependencies will be downloaded
)
