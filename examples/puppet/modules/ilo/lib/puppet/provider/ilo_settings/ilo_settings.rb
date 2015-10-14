require 'puppet/provider/ilo'

Puppet::Type.type(:ilo_settings).provide(:ilo_settings, :parent => Puppet::Provider::Ilo) do
    @doc = "Manages iLO settings"

    attr_reader :supported
    @supported = {
        'network' => {
            :reader => 'get_network_settings',
            :writer => 'mod_network_settings',
        },
        'global' => {
            :reader => 'get_global_settings',
            :writer => 'mod_global_settings',
        },
        'dir' => {
            :reader => 'get_dir_config',
            :writer => 'mod_dir_config',
        },
        'snmp' => {
            :reader => 'get_snmp_im_settings',
            :writer => 'mod_snmp_im_settings',
        },

    }

    mk_resource_methods

    def self.lookup(device, id)
        fail Puppet::Error, "Unknown settings type #{id}" unless @supported.include?(id);
        settings = device.transport.get(@supported[id][:reader])
        {:name => id, :writer => @supported[id][:writer], :settings => settings}
    end

    def flush
        device.transport.call(properties[:writer], *properties[:settings].map{|k,v| "#{k}=#{v}"})
    end
end
