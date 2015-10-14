require 'json'
require 'puppet/provider/ilo'

module Puppet::Util::NetworkDevice::Ilo
  class Transport

    attr_reader :hostname

    def initialize(hostname, local)
        @hostname = hostname
        @local = local
        @provider = Puppet::Provider::Ilo.new(hostname)
        @provider.mkcommands
        @cachedir = File.join(Puppet[:confdir], 'cache')
        Dir.mkdir(@cachedir) unless File.exist?(@cachedir)
        @cachable = {
            'get_fw_version' => {
                :updaters => ['update_rib_firmware'],
                :ttl => 86400 * 3,
            },
            'get_global_settings' => {
                :updaters => ['mod_global_settings'],
                :ttl => 86400 * 2,
            },
            'get_network_settings' => {
                :updaters => ['mod_network_settings'],
                :ttl => 86400,
            },
            'get_all_licenses' => {
                :updaters => ['activate_license'],
                :ttl => 86400 * 4,
            },
            'get_dir_config' => {
                :updaters => ['mod_dir_config'],
                :ttl => 86400,
            },
            'get_snmp_im_settings' => {
                :updaters => ['mod_snmp_im_settings'],
                :ttl => 86400,
            },
            'get_user' => {
                :updaters => ['add_user', 'mod_user', 'delete_user'],
                :ttl => 86400,
            },
            'get_all_users' => {
                :updaters => ['add_user', 'delete_user'],
                :ttl => 86400,
            },
            'get_oa_info' => {
                :updaters => [],
                :ttl => 86400 * 3,
            },
        }
        @cachable.each do |k, v|
            v[:updaters].push('factory_defaults')
        end
    end

    def call(method, *args)
        @cachable.each do |reader,opts|
            if(opts[:updaters].include?(method))
                cachefile = File.join(@cachedir, reader)
                if File.exists?(cachefile)
                    File.unlink(cachefile)
                end
                Dir.glob(cachefile + '_*') do |filename|
                    File.unlink(filename)
                end
             end
        end
        args = args.clone
        args.insert(0, '--json', @hostname, method)
        args.insert(0, '-Plocal') if @local
        @provider.hpilo_cli(*args)
    end

    def get(method, *args)
        args = args.clone
        args.insert(0, '--json', @hostname, method)
        if(@cachable.include?(method))
            cachefile = File.join(@cachedir, method)
            if(args.length > 3)
                cachefile += '_' + args.slice(3,args.length).join()
            end
            cutoff = Time.new - @cachable[method][:ttl]
            if(File.exist?(cachefile) && File.mtime(cachefile) > cutoff)
                args.insert(0, '--read-response', cachefile)
            else
                if File.exist?(cachefile)
                    File.unlink(cachefile)
                end
                args.insert(0, '--save-response', cachefile)
            end
        end
        args.insert(0, '-Plocal') if @local
        json = @provider.hpilo_cli(*args)
        JSON.parse(json)
    end

    def check_password(login, password)
        begin
            @provider.hpilo_cli('-l', login, '-p', password, @hostname, 'get_fw_version')
            true
        rescue
            false
        end
    end

    def fw_config()
        cachefile = File.join(File.dirname(Puppet[:confdir]), 'firmware.conf.json')
        cutoff = Time.new - 86400
        if(!File.exist?(cachefile) || File.mtime(cachefile) < cutoff)
            json = @provider.python("-c", "import hpilo_fw, json; print(json.dumps(hpilo_fw.config()))")
            f = File.new(cachefile, 'w')
            f.write(json)
            f.close()
        end
        f = File.new(cachefile)
        json = f.read()
        f.close()
        JSON.parse(json)
    end
  end
end
