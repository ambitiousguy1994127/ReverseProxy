Apache Modules for SSO and Access Control
==============

1. Installing Apache
--------------

This commands will install apache2 from packages with already 
built-in mod_proxy support in CentOS or RedHat Linux.
*Run this commands as root:*

	yum install httpd

For installing Apache from sources using mod_proxy,
the following commands should be done:

	./configure --enable-mods-shared="proxy proxy_http proxy_ftp proxy_connect".
	sudo make install.

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

	git clone https://username:password@github.com/OpenIAM/apache-modules.git apache-modules

you can omit password here, but will be prompted for type password:

	git clone https://username@github.com/OpenIAM/apache-modules.git apache-modules

Then clone for first time, you can see this messsage:

	Initialized empty Git repository in /home/tester/apache-modules/.git/
	The authenticity of host 'github.com (204.232.175.90)' can't be established.
	RSA key fingerprint is 12:34:56:78:90:12:34:56:78:90:12:34:56:78:90:12.
	Are you sure you want to continue connecting (yes/no)

if so, type **yes**

if you already have sources cloned from github, you can update it, using this command:

	git pull

If everithing ok, you will see

	Receiving objects: 100% ... done.
	Recolving deltas: 100% ... done.

Go to the apache module sources directory:

	cd apache-modules/src/access

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

Copy ".spec" file from ~/apache-modules/src/access to ~/rpmbuild/SPECS

	cp ~/apache-modules/src/access/*.spec ~/rpmbuild/SPECS

Check contents of ~/apache-modules/src/access/Makefile. $DEFS variable should not contain any debug defines,
or debug information will be printed. Check that it is not contain -DDEBUG=1
DEFS should look like this:

	DEFS=-DBIG_JOINS=1 -DUSE_LIBXML=1

Copy sources from ~/apache-modules/src/access to ~/rpmbuild/SOURCES/mod_iam_authn-3.0.0

	cp -r ~/apache-modules/src/access/ ~/rpmbuild/SOURCES/mod_iam_authn-3.0.0

Compress ~/rpmbuild/SOURCES/mod_iam_authn-3.0.0

	cd ~/rpmbuild/SOURCES
	tar -cvzf mod_iam_authn-3.0.0.tar.gz mod_iam_authn-3.0.0
	rm -rf mod_iam_authn-3.0.0

*Be very carefull with 'rm -rf' command*

Build rpm package for current platform

	cd ~/rpmbuild
	rpmbuild -bb SPECS/mod_iam_authn-3.0.0.spec

Resulting RPM will be in ~/rpmbuild/RPMS

apxs (tool for building modules for apache) doesn't support cross-compiling. This mean, that to build both
i386 and x86_64 RPMs, need to build RPM twice on 32-bit and 64-bit platform.

3. Installing using RPM pacakge
--------------

Download RPM for your platform. For this moment this rpms available:

- mod_iam_authn-3.0.0-1.i686.rpm
- mod_iam_authn-3.0.0-1.x86_64.rpm

Install RPM with root privilegies, using this command:

	rpm -i mod_iam_authn-3.0.0-1.i686.rpm

Or, for 64bit platform:

	rpm -i mod_iam_authn-3.0.0-1.x86_64.rpm

During Installation process, Apache web server should be restarted.
If not, you can restart it manually:

	/etc/init.d/httpd restart

Don't forget to restart or reload Apache web server after any changes in 
configuration.


4. Settings and Configuration
--------------

The following lines should be add in httpd.conf file:

	LoadModule proxy_module modules/mod_proxy.so
	LoadModule proxy_connect_module modules/mod_proxy_connect.so
	LoadModule proxy_http_module modules/mod_proxy_http.so 

This command enable using network request from inside apache and apache modules
(including libcurl), and should be run with root privilegies:

	setsebool -P httpd_can_network_connect 1

