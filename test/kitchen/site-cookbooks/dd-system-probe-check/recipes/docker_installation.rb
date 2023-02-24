# prereqs
case node[:platform]
  when 'ubuntu', 'debian'
    apt_update
end

case node[:platform]
when 'ubuntu', 'debian'
  package 'gnupg'

  package 'unattended-upgrades' do
    action :remove
  end

  package 'xfsprogs'
when 'centos'
  package 'xfsprogs'
end

# install docker-engine
case node[:platform]
when 'amazon'
  package 'docker'
when 'redhat'
  execute 'install docker-compose' do
    command <<-EOF
      dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
      dnf install -y docker-ce-19.03.13
    EOF
    user 'root'
    live_stream true
  end
else
  remote_file '/tmp/ci/system-probe/get-docker.sh' do
    source 'https://get.docker.com'
    owner 'root'
    group 'root'
    mode '0744'
    action :create
    sensitive true
  end
  execute 'install_docker' do
    command 'sh /tmp/ci/system-probe/get-docker.sh'
    user 'root'
    live_stream true
  end
end

# start docker-engine
case node[:platform]
when 'centos', 'fedora', 'redhat', 'sles', 'amazon'
  service 'docker' do
    action [ :enable, :start ]
  end
end

# install docker-compose
docker_ce_version = `uname -s`.strip.downcase + '-' + `uname -m`.strip
remote_file '/usr/bin/docker-compose' do
  source "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-#{docker_ce_version}"
  owner 'root'
  group 'root'
  mode '0755'
  action :create
  sensitive true
end
