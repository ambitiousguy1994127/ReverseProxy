##
##


ifeq ($(OS),Windows_NT)
    TARGET = WIN32
ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
        ARCH = AMD64
endif
ifeq ($(PROCESSOR_ARCHITECTURE),x86)
        ARCH = IA32
endif
else
    UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
        TARGET = Linux

ifneq ("$(wildcard /etc/redhat-release)","")
DIST=REDHAT
VER=$(shell  uname -r | sed s/.*el/el/ | sed s/[.].*//)
else
DIST=$(lsb_release -si)
VER=$(lsb_release -sr)
endif

endif
ifeq ($(UNAME_S),Darwin)
        TARGET = OSX
endif
ifeq ($(UNAME_S),Solaris)
        TARGET = SOLARIS
endif
ifeq ($(UNAME_S),SunOS)
        TARGET = SOLARIS
endif
    UNAME_P := $(shell uname -p)
ifeq ($(UNAME_P),x86_64)
        ARCH = AMD64
endif
ifneq ($(filter %86,$(UNAME_P)),)
        ARCH = IA32
endif
ifneq ($(filter arm%,$(UNAME_P)),)
        ARCH = ARM
endif
endif

ifeq ($(TARGET),Linux)
ifeq ($(DIST), REDHAT)
ifeq ($(VER),el5)
    apxspath=/usr/sbin/
    SHARED_CACHING=-DSHARED_CACHE=1
#	-DLOG_SHARED_ERRORS=1
endif
ifeq ($(VER),el6)
    apxspath=/usr/sbin/
    SHARED_CACHING=-DSHARED_CACHE=1
#	-DLOG_SHARED_ERRORS=1
endif

        builddir=.
        top_srcdir=/etc/httpd
ifeq ($(ARCH),AMD64)
            top_builddir=/usr/lib64/httpd
            include /usr/lib64/httpd/build/special.mk
else
    	    top_builddir=/usr/lib/httpd
            include /usr/lib/httpd/build/special.mk
endif
        installdir=/etc/httpd/modules
endif
#top_srcdir=/usr/share/apache2
#top_builddir=/usr/share/apache2
#include /usr/share/apache2/build/special.mk
endif
ifeq ($(TARGET),OSX)
    builddir=.
    top_srcdir=/usr
    top_builddir=/usr/share/httpd
    include /usr/share/httpd/build/special.mk
endif


APXS=$(apxspath)apxs
APACHECTL=$(apachectlpath)apachectl

#   additional defines, includes and libraries
DEFS=-DBIG_JOINS=1 $(SHARED_CACHING)
INCLUDES= \
    -I. \
    -I/usr/include/libxml2 \
    -I./kerberos \
    -I./kerberos/spnegokrb5 \
    -I./3rdparty/jsmn \

#-I/usr/include/apr-1 -I/usr/include/apr-1.0

LIBS=-lcurl -lcrypto -lxml2

SOURCES= \
    mod_iam_authn.c \
    parse_soap_xml.c \
    curl_recv_data.c \
    date_utils.c \
    str_utils.c \
    memcache_utils.c \
    realloc_utils.c \
    iam_substitute.c \
    shared_mem.c \
    shared_cache_utils.c \
    read_cert.c \
    parse_cert_response.c \
    parse_jsmn.c \
    jsmn_utils.c \
    ./kerberos/spnegokrb5/accept_sec_context.c \
    ./kerberos/spnegokrb5/external.c \
    ./kerberos/spnegokrb5/der_put.c \
    ./kerberos/spnegokrb5/der_get.c \
    ./kerberos/spnegokrb5/asn1_NegTokenInit.c \
    ./kerberos/spnegokrb5/asn1_NegTokenTarg.c \
    ./kerberos/spnegokrb5/asn1_MechType.c \
    ./kerberos/spnegokrb5/asn1_MechTypeList.c \
    ./kerberos/spnegokrb5/asn1_ContextFlags.c \
    ./kerberos/spnegokrb5/der_length.c \
    ./kerberos/spnegokrb5/der_free.c \
    ./kerberos/spnegokrb5/der_copy.c \
    ./kerberos/spnegokrb5/decapsulate.c \
    $(wildcard ./3rdparty/jsmn/*.c)

main:
	$(APXS) $(INCLUDES) $(DEFS) -c $(SOURCES) $(LIBS)

#   the default target
all: main

#   install the shared object file into Apache 
install: main
	sudo $(APXS) -i mod_iam_authn.la
	/etc/init.d/httpd stop
#	$(APACHECTL) stop
	cp .libs/mod_iam_authn.so $(installdir)/mod_iam_authn.so

clean:
	for i in . ./kerberos/spnegokrb5; do \
		$(RM) $$i/*.{o,so,a,la,lo,slo} core; \
		$(RM) -rf $$i/.libs; \
	done

