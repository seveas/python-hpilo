require 'puppet/util/network_device/ilo/facts'
require 'puppet/util/network_device/ilo/transport'
require 'uri'

class Puppet::Util::NetworkDevice::Ilo::Device

    attr_accessor :hostname, :transport, :local

    def initialize(uri, option = {})
        uri = URI.parse(uri)
        @hostname = uri.host
        @local = uri.scheme == 'ilo'
        @option = option

        Puppet.debug("(iLO device) connecting to iLO #{@hostname} #{@option.inspect}.")
        @transport = Puppet::Util::NetworkDevice::Ilo::Transport.new(@hostname, @local)
        Puppet.debug("Transport created")
    end

    def facts
        @facts = Puppet::Util::NetworkDevice::Ilo::Facts.new(@transport)
        facts = @facts.retrieve
        Puppet.debug("(iLO device) Facts retrieved: #{facts.inspect}")
        facts.each do |k,v| Facter.add(k) do setcode do v end end end
        facts
    end

end
