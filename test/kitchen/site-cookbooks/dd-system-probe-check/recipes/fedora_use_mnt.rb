return unless platform?('fedora') && !Chef::SystemProbeHelpers::azure?(node)

script 'use mnt' do
  interpreter "bash"
  code <<-EOH
    mkdir -p /mnt/system-probe-tests
    mkdir -p /mnt/kitchen-dockers
    chmod 0777 /mnt/system-probe-tests /mnt/kitchen-dockers
    ln -s /mnt/system-probe-tests /tmp/system-probe-tests
    ln -s /mnt/kitchen-dockers /tmp/kitchen-dockers
  EOH
end
