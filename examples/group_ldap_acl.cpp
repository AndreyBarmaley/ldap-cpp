/***************************************************************************
 *   Copyright (C) 2008 by Andrey Afletdinov                               *
 *   afletdinov@mail.dc.baikal.ru                                          *
 *                                                                         *
 *   external acl for squid                                                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <fstream>
#include <iostream>
#include <list>
#include <algorithm>
#include <cctype>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cldap.h"
#define VERSION "0.7"

void help(const std::string & name)
{
    std::cout << name << " version " << VERSION << std::endl;
    std::cout << "Usage: " << name << " [OPTIONS]" << std::endl;
    std::cout << "  -H    URI connect LDAP, (ldaps://ldap.server.com)" << std::endl;
    std::cout << "  -b    full DN to group" << std::endl;
    std::cout << "  -a    search attributes (defaults memberUid)" << std::endl;
    std::cout << "  -f    path to authorization file (anonymous bind defaults)" << std::endl;
    std::cout << "  -i    insensitive" << std::endl << std::endl;
    std::cout << "  -h    print this help and exit" << std::endl << std::endl;
    std::cout << "  example squid ACL:" << std::endl;
    std::cout << "  external_acl_type type_comp_allow_map ttl=20 children=4 %SRC /path/to/group_ldap_acl -H ldaps://ldap.org -b cn=deny_computers,ou=group,dc=org" << std::endl;
    std::cout << "  acl COMP_ALLOW external type_comp_boss_map" << std::endl;
    std::cout << "  ..." << std::endl;
    std::cout << "  http_access deny !COMP_ALLOW" << std::endl << std::endl;
    std::cout << "  # for check %LOGIN need define proxy_auth above" << std::endl;
    std::cout << "  external_acl_type type_users_map ttl=20 children=10 %LOGIN /path/to/group_ldap_acl -H ldaps://ldap.org -b cn=allow_user,ou=group,dc=org" << std::endl;
    std::cout << "  acl USERS_ALLOW external type_users_map" << std::endl;
    std::cout << "  ..." << std::endl;
    std::cout << "  http_access allow USERS_ALLOW" << std::endl << std::endl << std::endl;
    std::cout << "  authorization file:" << std::endl;
    std::cout << "  login dn" << std::endl;
    std::cout << "  password" << std::endl << std::endl;
}

void parse(const std::string & file, std::string & login, std::string & passwd)
{
    std::fstream stream(file.c_str(), std::ios::in);

    if(stream.fail())
    {
        std::cerr << "read file: " + file + ", skipping..." << std::endl;
        return;
    }

    stream >> login;
    stream >> passwd;

    stream.close();
}

void lower(std::string & str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

int main(int argc, char **argv)
{
    int c;

    std::string uri, group_dn, login, passwd, authfile;
    std::string attr("memberUid");
    const std::string name(argv[0]);
    bool insensitive = false;

    while((c = getopt(argc, argv, "H:b:f:a:ih")) != -1)
    {
       switch(c)
       {
            case 'H':
                uri = std::string(optarg);
                break;

            case 'b':
                group_dn = std::string(optarg);
                break;

            case 'a':
                attr = std::string(optarg);
                break;

            case 'f':
                authfile = std::string(optarg);
                break;

            case 'i':
		insensitive = true;
                break;

            case 'h':
                help(name);
                return 0;

           default: break;
       }
    }

    if(uri.empty() || group_dn.empty())
    {
        help(name);
        return 0;
    }

    if(authfile.size()) parse(authfile, login, passwd);

    Ldap::Server ldap;

    ldap.Connect(uri);

    if(ldap.Error())
    {
        std::cout << "error: " <<  ldap.Message() << std::endl;

        return 1;
    }

    ldap.Bind(login, passwd);

    if(ldap.Error())
    {
        std::cout << "error: " <<  ldap.Message() << std::endl;

        return 1;
    }

    std::string stream;

    struct in_addr in;
    struct hostent *hp;

    while(std::cin >> stream)
    {
        if(ldap.Ping() && ldap.Search(group_dn, Ldap::BASE))
        {
            std::list<std::string> values;

            if(insensitive)
            {
        	lower(stream);
        	std::for_each(values.begin(), values.end(), lower);
	    }

            (*ldap.Entries().begin()).GetValues(attr, values);

            if(values.end() != std::find(values.begin(), values.end(), stream)) std::cout << "OK" << std::endl;
            else
            // possible ip address (3 dots)
            if(3 == std::count(stream.begin(), stream.end(), '.') &&
                inet_aton(stream.c_str(), &in) &&
                (hp = gethostbyaddr((char *) &in.s_addr, sizeof(in.s_addr), AF_INET)))
            {
                std::string hostname(hp->h_name);
    		if(insensitive) lower(hostname);

                if(values.end() != std::find(values.begin(), values.end(), hostname)) std::cout << "OK" << std::endl;
                else std::cout << "ERR" << std::endl;
            }
            else
                std::cout << "ERR" << std::endl;
        }
        else
        {
            std::cerr << name << ": connection down" << std::endl;
            std::cout << "ERR" << std::endl;
        }

        std::cout.flush();
    }

    ldap.Disconnect();

    return 0;
}
