
# agent directoy within the container file system, contents from C:\mnt copied here during builds
$agentdir = "C:\dev\go\src\github.com\DataDog\datadog-agent"
if (!(Test-Path $agentdir)) {
    New-Item -ItemType Directory -Path $agentdir
}

# add GOPATH to PATH
if (!($env:Path.Contains($env:GOPATH))) {
    $env:path  += ";$env:GOPATH"
}

# enable ridk (Ruby VS dev tools)
& ridk enable

# it worked
exit 0
