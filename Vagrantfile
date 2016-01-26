# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/trusty32"
  config.ssh.forward_agent = true
  config.ssh.forward_x11 = true
  config.vm.provision :shell, inline: <<-SHELL
    sudo apt-get -y install build-essential git
  SHELL
end
