require 'puppet/util/network_device/ilo/device'
require 'puppet/provider/network_device'

class Puppet::Provider::Ilo < Puppet::Provider::NetworkDevice
    attr_writer :device

    def self.device(url)
        @device = Puppet::Util::NetworkDevice::Ilo::Device.new(url)
        @device
    end

    def self.mkcommands
        @commands ||= {}
        commands :python => "python", :hpilo_cli => "hpilo_cli";
    end

    def mkcommands
        self.class.mkcommands
    end
end
