/* Simple C program that connects to MySQL Database server*/
#include <mysql.h>
#include <stdio.h>
int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Please specify the username and password\n%d\n", argc);
		return -1;
	}
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	const char *server = "localhost";
	const char *user = argv[1];
	const char *password = argv[2];
	const char *database = "openiam";
	conn = mysql_init(NULL);
	/* Connect to database */
	if (!mysql_real_connect(conn, server,
				user, password, database, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		return -1;
	}
	/* send SQL query */
	if (mysql_query(conn, "show tables")) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		return -1;
	}
	res = mysql_use_result(conn);
	/* output table name */
	printf("MySQL Tables in mysql database:\n");
	while ((row = mysql_fetch_row(res)) != NULL)
		printf("%s \n", row[0]);
	/* close connection */
	mysql_free_result(res);
	mysql_close(conn);
}
