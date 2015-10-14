Puppet::Type.newtype(:ilo_settings) do
    desc "Manage iLO settings"

    apply_to_device

    newparam(:name, :namevar=>true) do
        desc "Which settings"
    end

    newproperty(:settings) do
        desc "The settings"

        def retrieve
            provider.settings
        end

        def insync?(is)
            @should.each do |should|
                is.keys.each do |key|
                    should.include?(key) || is.delete(key)
                end
                should.keys.each do |key|
                    return false if should[key].to_s != is[key].to_s
                end
            end
            true
        end

    end

end
