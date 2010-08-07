pam_sqlite 0.3
=============

Introduction
============

This module provides support to authenticate against SQLite
tables for PAM-enabled appliations.

This module is based on pam_pgsql module.

Compilation & Installation
==========================

pam_sqlite is now autoconf'ed, thus, compiling should be a matter
of:

    $ ./configure
    $ make
    $ make install

Compilation has been tested on RedHat Linux 7.3.

You will need to have SQLite library and header files
for this module to compile.

See test.c for an example application that authenticates using
this module.

Configuration
=============

For the service you wish the module to be used, you need
to edit the /etc/pam.d/<service> file or /etc/pam.conf, and 
add the relevant lines.

For example:

auth        required    pam_sqlite.so 
account     required    pam_sqlite.so
password    required    pam_sqlite.so

Configure the database, and table the module should use with
the configuration file /etc/pam_sqlite.conf. An example of
this file:

database = /etc/sysdb
table = account
user_column = user_name
pwd_column = user_password
expired_column = acc_expired
newtok_column = acc_new_pwreq
debug

expired_column tells PAM if the user account has expired. Set it to '1'
or 'y' if it has.

newtok_column tells PAM if the user needs a new password. Set it to '1'
or 'y' if it does.

Note that for backwards compatibility with earlier versions, options specified
in the configuration file can be supplied as module arguments as well. Module
arguments will override the configuration file.

Configuration Options
=====================

    database            - the database which should be connected to
    table               - the name of the table to query
    user_column         - the column containing usernames
    pwd_column          - the column containing the passwords
    expired_column      - this column should contain '1' or 'y' if the account
                          has expired
    newtok_column       - this column should contain '1' or 'y' if the user
                          needs to change their password
    debug               - this is a standard module option that will enable
                          debug output to syslog (takes no values)
    pw_type             - specifies the password encryption scheme, can be one
                          of 'clear', 'md5', or 'crypt'. defaults to 'clear'.
    config_file         - specifies the path to a file to read for further
                          configuration options
    sql_verify          - specifies SQL template to use when verifying the
                          the password for a user
    sql_check_expired   - SQL template to use when checking for account expiry.
    sql_check_newtok    - SQL template to use when checking to see if the user
                          needs to change their password.
    sql_set_passwd      - SQL template to use when updating the password for
                          and user.


SQL Templates
=============

SQL templates are printf-inspired format strings.  The following escape
sequences are understood:

    %%      - literal % character

    %U      - The username (provided by PAM).  It will be quoted for use
              in the SQL.
    %P      - The password, either entered by the user or the new password
              to use when changing it.  It will be quoted for use in SQL.

    %O<char> - an option from the configuration; the following options are
               supported:

    %Op     - value of pwd_column
    %Ou     - value of user_column
    %Ot     - value of table
    %Ox     - value of expired_column
    %On     - value of newtok_column

vim:et:
