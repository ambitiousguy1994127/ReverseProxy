APR_FLAGS=`apr-1-config --cflags --link-ld`

XML_SOURCES= \
    xml_test.c\
    ../access/parse_soap_xml.c\
    ../access/parse_soap_str.c\
    ../access/iam_str_utils.c\
    ../access/curl_recv_data.c\
    ../access/xml_utils.c\

mysql:
	gcc -o mysql_test -I/usr/include/mysql -DBIG_JOINS=1  -fno-strict-aliasing  -g mysql_test.c -L/usr/lib/mysql  -lmysqlclient -lpthread -lz -lm -lrt -ldl
	#gcc -o output-file $(mysql_config --cflags) mysql_test.c $(mysql_config --libs)

aes:
	gcc -Wall -o aes_test -g aes_test.c -lcrypto 

http-test:
	gcc -Wall $(APR_FLAGS) -o http_test -O2 http_test.c ../access/curl_recv_data.c -lcurl

xml-test:
	gcc -Wall -I/usr/include/libxml2 $(APR_FLAGS) -O2 -o xml_test $(XML_SOURCES) -lxml2 -lcurl

all: aes http-test xml-test
