class ilo::proxy($devices) {
    package{['ruby-json', 'python-hpilo']:
        ensure => latest,
    }
    concat{"/etc/puppet/device.conf":
        ensure => present,
        mode   => 400,
        owner  => root,
        group  => root,
    }
    device{$devices:}

    define device() {
        concat::fragment{"ilo-device-$name":
            target => "/etc/puppet/device.conf",
            content => template("ilo/ilo-device.erb")
        }
    }
}

