# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.hostname = "django-auth-backend"

  config.vm.network "forwarded_port", guest: 8005, host: 8005

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4092
    vb.cpus = 1
  end

  config.vm.provision :shell do |s| 
    s.path = "provision.sh"
    s.args = "env.txt"
  end
end
