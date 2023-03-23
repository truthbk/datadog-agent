#
# Cookbook Name:: dd-agent-install
# Recipe:: _print_windows_installer_log.rb
#
# Copyright (C) 2023-present Datadog
#
# All rights reserved - Do Not Redistribute
#

ruby_block "Print install logs" do
  only_if { ::File.exists?(installer_log_file_name) }
  block do
    # Use warn, because Chef's default "log" is too chatty
    # and the kitchen tests default to "warn"
    Chef::Log.warn(File.open(installer_log_file_name, "rb:UTF-16LE", &:read).encode('UTF-8'))
  end
end

