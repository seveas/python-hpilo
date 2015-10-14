require 'puppet/provider/ilo'

Puppet::Type.type(:ilo_firmware).provide(:ilo_firmware, :parent => Puppet::Provider::Ilo) do
    @doc = "Manages iLO firmware"

    def firmware_version() @property_hash[:firmware_version] end

    def self.lookup(device, id)
        version = device.transport.get('get_fw_version')
        {
            :name                 => version['management_processor'],
            :management_processor => version['management_processor'],
            :firmware_version     => version['firmware_version'],
            :firmware_date        => version['firmware_date']
        }
    end

    def fw_config
        old_https_proxy = ENV['https_proxy']
        old_http_proxy = ENV['http_proxy']
        begin
            ENV['http_proxy'] = ENV['https_proxy'] = resource[:http_proxy]
            device.transport.fw_config
        ensure
            ENV['https_proxy'] = old_https_proxy
            ENV['http_proxy'] = old_http_proxy
        end

    end

    def install
        Puppet::debug("Installing firmware version #{@resource[:ensure]}")
        old_https_proxy = ENV['https_proxy']
        old_http_proxy = ENV['http_proxy']
        begin
            device.transport.call('update_rib_firmware', "version=#{@resource[:ensure]}")
        ensure
            ENV['https_proxy'] = old_https_proxy
            ENV['http_proxy'] = old_http_proxy
        end
    end
end
