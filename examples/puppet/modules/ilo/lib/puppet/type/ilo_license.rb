Puppet::Type.newtype(:ilo_license) do
    desc "Manage iLO licenses"

    apply_to_device

    newparam(:name, :namevar=>true) do
        desc "License name"
    end

    newproperty(:key) do
        desc "License key"
    end

end
