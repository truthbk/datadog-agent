#
# Cookbook Name:: dd-agent-install
# Recipe:: _repair_windows_install
#
# Copyright (C) 2021-present Datadog


installer_log_file_name = ::File.join(Chef::Config[:file_cache_path], 'repair.log').gsub(File::SEPARATOR, File::ALT_SEPARATOR || File::SEPARATOR)

powershell_script "repair-agent" do
  code <<-EOF
  $product_code = (Get-WmiObject Win32_Product | Where-Object -Property Name -eq 'Datadog Agent').IdentifyingNumber
  Start-Process msiexec.exe -Wait -ArgumentList '/q','/log','#{installer_log_file_name}','/fa',$product_code
  EOF
end

include_recipe 'dd-agent-install::_print_windows_installer_log'
