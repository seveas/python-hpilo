require 'puppet/util/network_device/ilo'

class Puppet::Util::NetworkDevice::Ilo::Facts

    attr_reader :transport

    def initialize(transport)
        @transport = transport
    end

    def retrieve
        facts = {
            'devicetype' => 'ilo',
            'users' => @transport.get('get_all_users'),
        }
        facts.merge! @transport.get('get_fw_version')
        begin
            facts.merge! Hash[@transport.get('get_oa_info').map{ |k,v| [ 'oa_'+ k, v ] }]
        rescue
        end
        Hash[facts.map{ |k,v| [ k.to_sym, v ] }]
    end
end
