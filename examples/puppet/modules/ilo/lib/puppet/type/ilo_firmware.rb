Puppet::Type.newtype(:ilo_firmware) do
    desc "Manage iLO firmware"

    apply_to_device

    ensurable do
        attr_accessor :latest

        newvalue(:latest) do
            begin
                provider.install
            rescue => detail
                self.fail "Could not update: #{detail}"
            end
        end

        newvalue(/./) do
            begin
                provider.install
            rescue => detail
                self.fail "Could not update: #{detail}"
            end
        end

        def insync?(is)
            @should.each do |should|
                case
                    when is == should
                        return true
                    when should == :latest && is == provider.fw_config[@resource.name.downcase]['version']
                        return true
                end
            end
            false
        end

        def retrieve
            provider.firmware_version
        end

        defaultto :latest

    end

    newparam(:name, :namevar=>true) do
        desc "Ilo type"

        validate do |value|
            unless value =~ /ilo[234]?/i
                fail Puppet::Error, "Unknown iLO type, '#{value}'"
            end
            if value.downcase != Facter.value(:management_processor).downcase
                fail Puppet::Error, "This server has an #{Facter.value(:management_processor)}, not an #{value}"
            end
        end

    end

    newparam(:http_proxy) do
        desc "HTTP proxy for downloading firmware"
        defaultto ""
    end
end
