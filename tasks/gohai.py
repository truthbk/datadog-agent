import io
import random
import re
import string
import sys
from typing import Dict, List, Optional, Tuple
from invoke import task
from invoke.context import Context, Result
from invoke.exceptions import Exit, ParseError, UnexpectedExit
from enum import Enum

DEFAULT_BASE_BRANCH = "main"
DEFAULT_CREATE_VM_PATH = "../test-infra-definitions"
PACKAGE_LIST = ["cpu", "memory", "platform"]

git_repo_url = "https://github.com/DataDog/datadog-agent.git"
cloned_name = "datadog-agent"
gohai_path = "pkg/gohai"
gohai_bin_name = "gohai"
base_output = "gohai_base.out"
target_output = "gohai_target.out"


class Arch(str, Enum):
    AMD64 = "amd64"
    ARM64 = "arm64"
    I386 = "386"


# some distros don't have up-to-date versions of Go in their repos so
# installing manually is a safer way
def _get_unix_go_setup(arch: Arch) -> str:
    go_url = f"https://go.dev/dl/go1.20.5.linux-{arch.value}.tar.gz"
    return f"""curl -L "{go_url}" --output go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz

    export GOPATH=$HOME/go
    export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
    """


def _get_apt_setup() -> str:
    return f"""sudo apt -y update
    sudo apt -y install git jq curl tar"""


def _get_dnf_setup() -> str:
    return f"""sudo dnf -y install git jq tar curl"""


def _get_yum_setup() -> str:
    return f"""sudo yum -y install git jq tar # no curl !"""


def _get_zypper_setup() -> str:
    return f"""sudo zypper --non-interactive in git-core jq curl tar"""


class Platform:
    def __init__(self, name: str, arch: Arch):
        self.name = name
        self.arch = arch

    def compare(self, ctx: Context, ssh_args: str, ssh_addr: str, base_branch: str, target_branch: str, package: str) -> Result:
        raise NotImplementedError()


class UnixPlatform(Platform):
    def __init__(self, name: str, arch: Arch):
        super().__init__(name, arch)

    def _get_package_setup(self):
        raise NotImplementedError()

    def _get_setup_script(self, base_branch: str, target_branch: str, package: str) -> Tuple[str, str, str]:
        # only clone /pkg/gohai from the datadog-agent repo
        script = f"""#!/bin/bash
        set -euo pipefail
        {self._get_package_setup()}
        {_get_unix_go_setup(self.arch)}

        function clone_and_run {{
            branch=$1
            outpath=$2

            #echo "Fetch gohai on $branch"
            rm -rf {cloned_name}
            # https://stackoverflow.com/questions/600079/how-do-i-clone-a-subdirectory-only-of-a-git-repository
            git clone -n --depth=1 --filter=tree:0 -b $branch {git_repo_url} {cloned_name}
            cd {cloned_name}
            git sparse-checkout set --no-cone "{gohai_path}"
            git checkout
            cd {gohai_path}
            go build
            # jq < 1.6 will error if redirecting the output without a filter
            ./{gohai_bin_name} --only {package} 2> $outpath.err | jq -S '.' > $outpath
        }}

        #echo "Fetching the versions to compare the output"
        (clone_and_run {base_branch} $PWD/{base_output})
        (clone_and_run {target_branch} $PWD/{target_output})
        """

        return script, f"~/{base_output}", f"~/{target_output}"

    def compare(self, ctx: Context, ssh_args: str, ssh_addr: str, base_branch: str, target_branch: str, package: str) -> Result:
        script, base_output, target_output = self._get_setup_script(base_branch, target_branch, package)
        script_name = "script.sh"

        ctx.run(f'ssh {ssh_args} {ssh_addr} -T "cat > {script_name}"', echo=True, in_stream=io.StringIO(script), hide="both")
        ctx.run(f'ssh {ssh_args} {ssh_addr} "chmod +x {script_name} && ./{script_name}"', echo=True, hide="both")
        result = ctx.run(f"ssh {ssh_args} {ssh_addr} diff '{base_output}' '{target_output}'", echo=True, warn=True, hide="both")
        return result


class Ubuntu(UnixPlatform):
    NAME = "ubuntu"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_apt_setup()


class AmazonLinux(UnixPlatform):
    NAME = "amazonlinux"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_yum_setup()


class Debian(UnixPlatform):
    NAME = "debian"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_apt_setup()


class Redhat(UnixPlatform):
    NAME = "redhat"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_yum_setup()


class Suse(UnixPlatform):
    NAME = "suse"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_zypper_setup()


class Fedora(UnixPlatform):
    NAME = "fedora"

    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_package_setup(self) -> str:
        return _get_dnf_setup()


class Windows(Platform):
    NAME = "windows"
    def __init__(self, arch: Arch):
        super().__init__(self.NAME, arch)

    def _get_setup_script(self, base_branch: str, target_branch: str, package: str) -> Tuple[str, str, str]:
        script = f"""
        # stops the script if one of the powershell functions fails
        # doesn't stop if an exe (eg. git or go) fails
        $ErrorActionPreference = "Stop"

        function Remove-If-Exists ($Path) {{
            if (Test-Path $Path) {{
                Remove-Item $Path -Recurse -Force
            }}
        }}

        # removing the progress bar reduces download time ~100x
        $global:ProgressPreference = "SilentlyContinue"

        Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.41.0.windows.1/MinGit-2.41.0-64-bit.zip" -OutFile "git.zip"
        Remove-If-Exists .\git
        Expand-Archive .\git.zip

        Invoke-WebRequest -Uri "https://go.dev/dl/go1.20.5.windows-amd64.zip" -OutFile "go.zip"
        Remove-If-Exists .\go
        Expand-Archive .\go.zip

        Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.6/jq-win64.exe" -OutFile "jq.exe"

        function Clone-And-Run ($Branch, $OutPath) {{
            cd ~
            Remove-If-Exists {cloned_name}

            # https://stackoverflow.com/questions/600079/how-do-i-clone-a-subdirectory-only-of-a-git-repository
            ~\git\cmd\git.exe clone -n --depth=1 --filter=tree:0 -b $branch {git_repo_url} {cloned_name}
            if ($lastexitcode -ne 0) {{ throw ("git error") }}
            cd {cloned_name}
            ~\git\cmd\git.exe sparse-checkout set --no-cone "{gohai_path}"
            if ($lastexitcode -ne 0) {{ throw ("git error") }}
            ~\git\cmd\git.exe checkout
            if ($lastexitcode -ne 0) {{ throw ("git error") }}
            cd {gohai_path}
            ~\go\go\\bin\go.exe build
            if ($lastexitcode -ne 0) {{ throw ("go error") }}
            ./{gohai_bin_name} --only {package} 2> $outpath.err | jq -S > $outpath
            if ($lastexitcode -ne 0) {{ throw ("gohai error") }}
        }}

        Clone-And-Run {base_branch} ~/{base_output}
        Clone-And-Run {target_branch} ~/{target_output}
        """
        return script, f"~/{base_output}", f"~/{target_output}"

    def compare(self, ctx: Context, ssh_args: str, ssh_addr: str, base_branch: str, target_branch: str, package: str) -> Result:
        script, base_output, target_output = self._get_setup_script(base_branch, target_branch, package)
        script_path = f"/tmp/gohai_compare_script-{self.name}-{self.arch.value}.ps1"
        with open(script_path, "w") as writer:
            writer.write(script)

        ctx.run(f'scp {ssh_args} {script_path} {ssh_addr}:script.ps1', echo=True, hide="both")
        ctx.run(f'ssh {ssh_args} {ssh_addr} "./script.ps1"', echo=True, hide="both")
        result = ctx.run(f"ssh {ssh_args} {ssh_addr} '~/git/usr/bin/diff.exe' '{base_output}' '{target_output}'", echo=True, warn=True, hide="both")
        return result


PLATFORM_LIST: List[Platform] = [
    Ubuntu(Arch.AMD64),
    Ubuntu(Arch.ARM64),
    AmazonLinux(Arch.AMD64),
    AmazonLinux(Arch.ARM64),
    Debian(Arch.AMD64),
    Debian(Arch.ARM64),
    Redhat(Arch.AMD64),
    Redhat(Arch.ARM64),
    Suse(Arch.AMD64),
    Suse(Arch.ARM64),
    Windows(Arch.AMD64),
    # Fedora(Arch.AMD64), # currently an issue with it
    # Fedora(Arch.ARM64), # not supported yet
    # Windows(Arch.ARM64), # not supported yet
    # windows & macos & centos ?
]


# creates a vm with the given Os and architecture
# create_vm_path is the path to the 'create-vm' invoke task
# pulumi_stack is the name of the stack to use
# returns the user@address to connect to the vm
def _create_vm(ctx: Context, os: str, arch: Arch, create_vm_path: str, pulumi_stack: Optional[str]) -> str:
    arch: str = arch.value

    create_vm_args = ["--no-use-fakeintake", "--no-install-agent", f"-o {os}", f"-r {arch}"]
    if pulumi_stack:
        create_vm_args.append(f"-s {pulumi_stack}")

    result = ctx.run(f"inv -r {create_vm_path} create-vm {' '.join(create_vm_args)}", echo=True, hide="both")

    SSH_REGEX = "You can run the following command to connect to the host `ssh ([!-~]+)@([!-~]+)`."
    match = re.search(SSH_REGEX, result.stdout)
    if not match:
        raise ParseError("Could not get the address of the vm.")

    user = match.group(1)
    addr = match.group(2)

    return f"{user}@{addr}"


@task(
    name="gohai_compare",
    iterable=["package"],
    help={
        "target_branch": "The target branch used to compare the output of Gohai. Defaults to the current branch.",
        "package": f"A package to compare. Possible values are [{', '.join(PACKAGE_LIST)}]. Defaults to all.",
        "base_branch": f"The branch used as a base to compare the output of Gohai. Defaults to {DEFAULT_BASE_BRANCH}.",
        "create_vm_path": f"The location of the 'create-vm' invoke task. Defaults to {DEFAULT_CREATE_VM_PATH}.",
        "ssh_auto_accept": "Whether to automatically accept ssh connections. Defaults to False.",
        "per_os_stack": "Whether to use a different pulumi stack for each OS, which avoids deleting them. Defaults to False.",
    },
)
def compare(
    ctx: Context,
    package: Optional[List[str]] = None,
    target_branch: Optional[str] = None,
    base_branch: Optional[str] = None,
    ssh_auto_accept: Optional[bool] = False,
    create_vm_path: Optional[str] = None,
    per_os_stack: Optional[bool] = False,
):
    """
    Compare two versions of gohai on multiple OS and architectures
    """

    print(f"ssh auto accept: {ssh_auto_accept}")
    print(f"per os stack: {per_os_stack}")

    if not create_vm_path:
        create_vm_path = DEFAULT_CREATE_VM_PATH
    print(f"create-vm path: '{create_vm_path}'")

    if not base_branch:
        base_branch = DEFAULT_BASE_BRANCH
    print(f"base branch: '{base_branch}'")

    if not target_branch:
        try:
            target_branch = ctx.run("git branch --show-current", hide="both").stdout.strip()
            # the command succeeds but prints nothing when in detached head
        except UnexpectedExit:
            pass
    if not target_branch:
        raise Exit("No target_branch was provided and current branch could not be determined.")
    print(f"target branch: '{target_branch}'")

    packages = package
    if not packages:
        packages = PACKAGE_LIST
    print(f"packages: [{', '.join(packages)}]")

    packages = [package.lower() for package in packages]
    for package in packages:
        if package not in PACKAGE_LIST:
            raise Exit(f"Unknown package '{package}'. Known packages are [{', '.join(PACKAGE_LIST)}].")
    package = ','.join(packages)

    base_ssh_args = '-o "UserKnownHostsFile=/dev/null" '
    if ssh_auto_accept:
        base_ssh_args += '-o "StrictHostKeyChecking no" '

    results: Dict[Platform, str] = {}
    for platform in PLATFORM_LIST:
        print()
        print(f"Creating {platform.name} {platform.arch.value} VM")

        pulumi_stack = None
        if per_os_stack:
            pulumi_stack = f"gohai-compare-{platform.name}-{platform.arch.value}"
        try:
            ssh_addr = _create_vm(ctx, platform.name, platform.arch, create_vm_path, pulumi_stack)
        except (UnexpectedExit, ParseError) as error:
            print(error, file=sys.stderr)
            results[platform] = "Error while creating the VM"
            continue

        if not ssh_auto_accept:
            print(f"Test connection to VM at {ssh_addr}")
            try:
                ctx.run(f"ssh {base_ssh_args} {ssh_addr} true", echo=True)
            except UnexpectedExit:
                print("Could not connect to VM")
                result[platform] = "Connection to VM failed"
                continue

        print("Setting-up the vm and getting the outputs on both branches")
        try:
            result = platform.compare(ctx, base_ssh_args, ssh_addr, base_branch, target_branch, package)
            if result:
                results[platform] = "The output was the same"
            else:
                results[platform] = f"The output was different:\n{result.stdout.strip()}"
        except UnexpectedExit as error:
            print(error, file=sys.stderr)
            results[platform] = "Error while setting up the VM"
            continue

    print()
    for platform, result in results.items():
        print(f"{platform.name}/{platform.arch.value}: {result}\n")
