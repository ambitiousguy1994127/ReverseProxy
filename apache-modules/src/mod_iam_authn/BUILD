Build OPENIAM Apache Modules for SSO and Access Control
==============

1. Installing Apache
--------------

This commands will install apache2 from packages with already 
built-in mod_proxy support in CentOS or RedHat Linux.
*Run this commands as root:*

	yum install httpd

2. Build from sources
--------------
*(can be skipped if you install using rpm installation package)*

Installing developer tools for build from sources
*Run this commands as root:*

	yum install gcc
	yum install make
	yum install httpd-devel
	yum install libxml2-devel
	yum install libcurl-devel
	yum install openssl-devel
	yum install git

Obtain sources from git repository (replace **username** and **password** with real github credentials)
*you can run next commands as user*

	git clone https://username:password@github.com/OpenIAM/iam-proxy-3.git

you can omit password here, but will be prompted for type password:

	git clone https://username@github.com/OpenIAM/iam-proxy-3.git

Then clone for first time, you can see this messsage:

	Initialized empty Git repository in /home/tester/apache-modules/.git/
	The authenticity of host 'github.com (204.232.175.90)' can't be established.
	RSA key fingerprint is 12:34:56:78:90:12:34:56:78:90:12:34:56:78:90:12.
	Are you sure you want to continue connecting (yes/no)

if so, type **yes**

if you already have sources cloned from github, you can update it, using this command:

	git pull

Go to the apache module sources directory:

	cd iam-proxy-3

clone jsmn library using script in 3rdparty/get_jsmn.sh
	cd 3rdparty
	./get_jsmn.sh
	cd ..

and build it

	make all

or build and install 
*Installation should be run as root*

	make install

3 Creating RPM package
--------------
*(can be skipped if you install using rpm installation package)*

Install packages for build rpms:
*this commands should be run as root*

	yum install rpm-build
	yum install redhat-rpm-config

After you have rpmbuild installed, the next step is to create the files and directories under your home directory that you need to build RPMs. 
To avoid possible system libraries and other files damage, you should *NEVER build an RPM with the root* user.
You should *always use an unprivileged user* for this purpose.

The instructions below will create a rpmbuild directory under your home directory to build RPMs. 

	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

Copy ".spec" file from iam-proxy-3/SPECS to ~/rpmbuild/SPECS

	cp SPECS/*.spec ~/rpmbuild/SPECS

Copy sources from iam-proxy-3 to ~/rpmbuild/SOURCES/mod_iam_authn-3.3.0

	cp -r ./ ~/rpmbuild/SOURCES/mod_iam_authn-3.5.0

Compress ~/rpmbuild/SOURCES/mod_iam_authn-3.5.0

	cd ~/rpmbuild/SOURCES
	tar -cvzf mod_iam_authn-3.5.0.tar.gz mod_iam_authn-3.5.0
	rm -rf mod_iam_authn-3.5.0

*Be very carefull with 'rm -rf' command*

Build rpm package for current platform

	cd ~/rpmbuild
	rpmbuild -bb SPECS/mod_iam_authn.spec

Resulting RPM will be in ~/rpmbuild/RPMS

apxs (tool for building modules for apache) doesn't support cross-compiling. This mean, that to build both
i386 and x86_64 RPMs, need to build RPM twice on 32-bit and 64-bit platform.

