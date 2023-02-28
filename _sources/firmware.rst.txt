Dealing with iLO firmware updates
=================================

One of the key features of python_hpilo is that it makes iLO firmware updates
painless. It can download the firmware for you, or you can feed it the .bin,
.scexe or .fwpkg files HP ships.

Note that the newest versions of the firmware, as of August 2020, are shipped
in a new format and you will need to use python-hpilo 4.4 or newer to extract
and use them. If you cannot upgrade, you can manually extract the .bin file
from the .fwpkg file (just open it with anything that can open zip files) and
pass the .bin file to python-hpilo.

From the CLI
------------
The method to call is :func:`update_rib_firmware`. To tell it which firmware
version to install, you can specify a version or a filename. To install the
latest version, you can use :data:`latest` as version. Information about
available version numbers can be found in `firmware.conf`_.

Some example commands::

    hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=1.28
    hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=latest
    hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware filename=CP007684.scexe
    hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware filename=ilo2_225.bin

If you just want to download the firmware, you can make :data:`hpilo_cli` do
that too::

    hpilo_cli download_rib_firmware all        # Download latest firmware for all iLO types
    hpilo_cli download_rib_firmware ilo4       # Download latest iLO 4 firmware
    hpilo_cli download_rib_firmware ilo4 1.50  # Download a specific firmware version
    hpilo_cli download_rib_firmware ilo4 all   # Download all firmware versions for iLO 4
    hpilo_cli download_rib_firmware all all    # Download all firmware versions for all iLO types

.. _`firmware.conf`: https://seveas.github.io/python-hpilo/firmware.conf

Using the API
-------------
As the CLI is merely a thin wrapper around the API, using the API is as expected::

    ilo = hpilo.Ilo(hostname, login, password)
    ilo.update_rib_firmware(version='latest')

But since firmware updates may take a while, the iLO can provide progress
messages, which your code may in turn show to your users. To receive these
progress message, pass a callable to the :func:`update_rib_firmware` function.
It will be called with single-line messages about the progress of the firmware
download, upload and flash processes. This example shows them to the user,
constantly overwriting the previous message::

    def print_progress(text):
        sys.stdout.write('\r\033[K' + text)
        sys.stdout.flush()

    ilo = hpilo.Ilo(hostname, login, password)
    ilo.update_rib_firmware(version='latest', progress=print_progress)
    print("")

Of course the firmware downloader can be used from the API as well::

    import hpilo_fw
    hpilo_fw.download('ilo4', path='/var/cache/ilo_fw/', progress=print_progress)
    hpilo_fw.download('ilo3 1.28', path='/var/cache/ilo_fw', progress=print_progress)

Using a local firmware mirror
-----------------------------
The firmware download functions connect to the internet to download firmware.
While they can be made to use a proxy, using the standard :data:`https_proxy`
and :data:`http_proxy` variables, it may be desirable to only download data
from inside your network.

To do this, you can set a variable in ilo.conf for the cli::

    [firmware]
    mirror = http://buildserver.example.com/ilo-firmware/

Or if you use the API, configure the firmware downloader, both the downloader
and the updater will then use your mirror::

    import hpilo, hpilo_fw
    hpilo_fw.config(mirror='http://buildserver.example.com/ilo-firmware/')

    ilo = hpilo.Ilo(hostname, login, password)
    ilo.update_rib_firmware(version='latest', progress=print_progress)
    print("")

    hpilo_fw.download('ilo4', progress=print_progress)

Your mirror should contain both :file:`firmware.conf`, and the :data:`.bin`
files for all firmware versions you want to support. You can create (and
auto-update via cron) such a mirror with a simple shellscript::

    #!/bin/sh

    cd /var/www/html/ilo-firmware
    wget -q https://seveas.github.io/python-hpilo/firmware.conf
    hpilo_cli -c /dev/null download_rib_firmware all all

This will download and extract the necessary files to
:file:`/var/www/html/ilo-firmware`.
