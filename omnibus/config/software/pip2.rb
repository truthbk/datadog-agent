name "pip2"

# The version of pip used must be at least equal to the one bundled with the Python version we use
# Python 2.7.18 bundles pip 20.3.4
default_version "20.3.4"

source :url => "https://github.com/pypa/pip/archive/#{version}.tar.gz",
       :sha256 => "cc21e03832d7ce96a0cf77ec1669661de35abb4366a9059fa54f1647e514ce3f",
       :extract => :seven_zip

relative_path "pip-#{version}"

build do
  license "MIT"
  license_file "https://raw.githubusercontent.com/pypa/pip/main/LICENSE.txt"

  if ohai["platform"] == "windows"
    python = "#{windows_safe_path(python_2_embedded)}\\python.exe"
  else
    python = "#{install_dir}/embedded/bin/python2"
  end
  command "#{python} -m pip install ."

  if windows?
    patch :source => "remove-python27-deprecation-warning.patch", :target => "#{windows_safe_path(python_2_embedded)}\\Lib\\site-packages\\pip\\_internal\\cli\\base_command.py"
  else
    patch :source => "remove-python27-deprecation-warning.patch", :target => "#{install_dir}/embedded/lib/python2.7/site-packages/pip/_internal/cli/base_command.py"
  end

  if ohai["platform"] != "windows"
    block do
      FileUtils.rm_f(Dir.glob("#{install_dir}/embedded/lib/python2.7/site-packages/pip-*-py2.7.egg/pip/_vendor/distlib/*.exe"))
    end
  end
end
