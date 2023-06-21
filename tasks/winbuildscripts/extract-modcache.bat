if exist c:\mnt\modcache.tar.gz (
    @echo Extracting modcache
    Powershell -C "get-date"
    Powershell -C "7z x c:\mnt\modcache.tar.gz -oc:\mnt"
    Powershell -C "7z x c:\mnt\modcache.tar -oc:\modcache"
    Powershell -C "get-date"
    del /f c:\mnt\modcache.tar.gz
    del /f c:\mnt\modcache.tar
    @echo Modcache extracted
) else (
    @echo modcache.tar.gz not found, dependencies will be downloaded
)
