require 'puppet/provider/ilo'

Puppet::Type.type(:ilo_license).provide(:ilo_license, :parent => Puppet::Provider::Ilo) do
    @doc = "Manages iLO settings"

    mk_resource_methods

    def self.lookup(device, id)
        instance = nil
        device.transport.get('get_all_licenses').each do |license|
            if license['license_type'] == id
                instance = {
                    :name => license['license_type'],
                    :key  => license['license_key'],
                }
            end
        end
        instance
    end

    def flush
        device.transport.call('activate_license', "key=#{properties[:key]}")
    end
end
