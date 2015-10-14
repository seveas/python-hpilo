Puppet::Type.newtype(:ilo_user) do
    desc "Manage iLO users"

    apply_to_device

    ensurable

    newparam(:name, :namevar=>true) do
        desc "User loginname"
    end

    def munge_boolean(value)
        case value
        when true, "true", :true
            true
        when false, "false", :false
            false
        else
            fail("munge_boolean only takes booleans")
        end
    end

    newproperty(:password) do
        desc "Password"
        def insync?(is)
            if(is == :absent)
                return provider.verify_password(@should[0])
            end
            is == @should[0]
        end
    end

    newparam(:password_atcreate) do
        desc "Password, only used when creating users"
    end

    newproperty(:display_name) do
        desc "User's display name"
    end

    newproperty(:admin_priv, :boolean => true) do
        desc "Admin privileges"
        newvalues(:true, :false)
        munge do |value| @resource.munge_boolean(value) end
    end

    newproperty(:config_ilo_priv, :boolean => true) do
        desc "iLO configuration privileges"
        newvalues(:true, :false)
        munge do |value| @resource.munge_boolean(value) end
    end

    newproperty(:remote_cons_priv, :boolean => true) do
        desc "Remote console privileges"
        newvalues(:true, :false)
        munge do |value| @resource.munge_boolean(value) end
    end

    newproperty(:reset_server_priv, :boolean => true) do
        desc "Server reset privileges"
        newvalues(:true, :false)
        munge do |value| @resource.munge_boolean(value) end
    end

    newproperty(:virtual_media_priv, :boolean => true) do
        desc "Virtual Media privileges"
        newvalues(:true, :false)
        munge do |value| @resource.munge_boolean(value) end
    end

    validate do
        if @parameters[:ensure].value != :absent && !Facter.value(:users).include?(@parameters[:name].value)
            unless @parameters.include?(:display_name)
                raise Puppet::Error, "A display_name is mandatory for #{@parameters[:name].value}"
            end
            unless (@parameters.include?(:password) or @parameters.include?(:password_atcreate))
                raise Puppet::Error, "A password is mandatory for #{@parameters[:name].value}"
            end
        end
    end
end
