Name:           mod_iam_authn
Version:        3.6.0
Release:        1%{?dist}
Summary:        Apache module for OpenIAM authentication and authorization
Group:          System Environment/Daemons
License:        Distributable
URL:            http://www.openiam.com/
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  httpd-devel
BuildRequires:  libxml2-devel
BuildRequires:  libcurl-devel
BuildRequires:  openssl-devel
Requires:       httpd
Requires:       libxml2
Requires:       libcurl
Requires:       openssl
Requires:       mod_ssl

%description
mod_iam_authn is a reverse proxy based on mod_proxy. And uses OpenIAM ESB Web services for URL federation.

%prep
echo $RPM_BUILD_ROOT
%setup -q

%build
echo "#define OPENIAM_MODULE_NAME \"%{name}-%{version}-%{release}\"" > version.h
echo "#undef DEBUG" > debug_dump_options.h
make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
install -m 755 .libs/%{name}.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules

%clean
rm -rf $RPM_BUILD_ROOT

%post
echo "mod_iam_authn installed"
echo "restart httpd to apply changes"

%files
%defattr(-,root,root)
%doc CHANGES  INSTALL  LICENSE  README  conf.d/*
%{_libdir}/httpd/modules/*.so

%changelog
