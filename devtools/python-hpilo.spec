Summary: Accessing HP iLO interfaces from python
Name: python-hpilo
Version: 4.4.4
Release: 1%{?dist}
Source0: http://pypi.python.org/packages/source/p/%{name}/%{name}-%{version}.tar.gz
License: GPL/APL
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Dennis Kaarsemaker <dennis@kaarsemaker.net>
Url: http://github.com/seveas/python-hpilo
BuildRequires: python python-setuptools

%description
This module will make it easy for you to access the Integrated Lights Out
management interface of your HP hardware. It supports RILOE II, iLO, iLO 2, iLO
3 and iLO 4. It uses the XML interface or hponcfg to access and change the iLO.

%prep
%setup -n %{name}-%{version}

%build
python setup.py build

%install
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
sed -e 's!/usr/bin/python!/usr/bin/python3!' -i $RPM_BUILD_ROOT/usr/bin/hpilo_cli

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%doc docs
%doc examples
%doc README.md
%doc CHANGES
%defattr(-,root,root)
