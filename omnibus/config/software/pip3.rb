name "pip3"
default_version "21.3.1"

skip_transitive_dependency_licensing true

dependency "python3"

source :url => "https://github.com/pypa/pip/archive/#{version}.tar.gz",
       :sha256 => "cbfb6a0b5bc2d1e4b4647729ee5b944bb313c8ffd9ff83b9d2e0f727f0c79714",
       :extract => :seven_zip

relative_path "pip-#{version}"

build do
  license "MIT"
  license_file "https://raw.githubusercontent.com/pypa/pip/main/LICENSE.txt"

  if ohai["platform"] == "windows"
    python = "#{windows_safe_path(python_3_embedded)}\\python.exe"
  else
    python = "#{install_dir}/embedded/bin/python3"
  end

  command "#{python} -m pip install ."

  if ohai["platform"] != "windows"
    block do
      FileUtils.rm_f(Dir.glob("#{install_dir}/embedded/lib/python3.*/site-packages/pip-*-py3.*.egg/pip/_vendor/distlib/*.exe"))
      FileUtils.rm_f(Dir.glob("#{install_dir}/embedded/lib/python3.*/site-packages/pip/_vendor/distlib/*.exe"))
    end
  end
end
