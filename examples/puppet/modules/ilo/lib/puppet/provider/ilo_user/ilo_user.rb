require 'puppet/provider/ilo'

Puppet::Type.type(:ilo_user).provide(:ilo_user, :parent => Puppet::Provider::Ilo) do
    @doc = "Manages iLO users"

    mk_resource_methods

    def self.lookup(device, id)
        begin
            user = device.transport.get('get_user', "user_login=#{id}")
        rescue
            return nil
        end
        {
           :name               => user['user_login'],
           :password           => :absent,
           :display_name       => user['user_name'],
           :admin_priv         => user['admin_priv'],
           :config_ilo_priv    => user['config_ilo_priv'],
           :remote_cons_priv   => user['remote_cons_priv'],
           :reset_server_priv  => user['reset_server_priv'],
           :virtual_media_priv => user['virtual_media_priv'],
        }
    end

    def verify_password(password)
        device.transport.check_password(name, password)
    end

    def propmap(props, oldprops=nil)
        props = props.map do |k,v|
            next if [:name, :ensure].include?(k)
            next if oldprops and props[k] == oldprops[k]
            if k == :display_name
                "user_name=#{v}"
            else
                "#{k}=#{v}"
            end
       end
       props.insert(0,"user_login=#{name}")
       props.reject do |p| p == nil end
    end

    def flush
        if properties[:ensure] == :absent
            device.transport.call('delete_user', "user_login=#{name}")
        elsif former_properties[:ensure] == :absent:
            cproperties = properties
            cproperties[:password] ||= resource[:password_atcreate]
            device.transport.call('add_user', *propmap(cproperties))
        else
            device.transport.call('mod_user', *propmap(properties, former_properties))
        end
    end
end
