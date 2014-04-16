Summary: Accessing HP iLO interfaces from python
Name: python-hpilo
Version: 2.6.1
Release: 1
Source0: %{name}-%{version}.tar.gz
License: GPL
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Dennis Kaarsemaker <dennis@kaarsemaker.net>
Url: http://github.com/seveas/python-hpilo
BuildRequires: python

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

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%doc docs/*.rst
%doc docs/_static
%doc docs/conf.py
%doc docs/Makefile
%doc README
%doc CHANGES
%defattr(-,root,root)
