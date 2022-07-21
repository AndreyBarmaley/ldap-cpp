/***************************************************************************
 *   Copyright (C) 2012 by Andrey Afletdinov                               *
 *   afletdinov@gmail.com                                                  *
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

#include <list>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <algorithm>

#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cldap.h"
#define VERSION "1.6"

#define HELPER_INPUT_BUFFER 8196

/* send OK result to Squid with a string parameter. */
#define SEND_OK(x)  std::cout << "OK " << x << std::endl

/* send ERR result to Squid with a string parameter. */
#define SEND_ERR(x) std::cout << "ERR " << x << std::endl

/* send BH result to Squid with a string parameter. */
#define SEND_BH(x)  std::cout << "BH " << x << std::endl

void help(const std::string & name)
{
    std::cout << name << " version " << VERSION << ", cldap: " << Ldap::getVersion() << std::endl <<
	"Usage: " << name << " [OPTIONS]" << std::endl <<
	"  -H    specify URI(s) referring to the ldap server(s); only the protocol/host/port fields are allowed; a list of URI, separated by commas." << std::endl <<
	"        URI connect LDAP, (ldaps://ldap.server.com or ldap://ldap1.server.com,ldaps://ldap2.server.com)" << std::endl <<
	"  -b    full DN to group" << std::endl <<
	"  -a    search attributes (defaults memberUid)" << std::endl <<
	"  -f    path to authorization file (anonymous bind defaults)" << std::endl <<
	"  -i    insensitive" << std::endl << std::endl <<
	"  -d    debug to syslog" << std::endl <<
	"  -h    print this help and exit" << std::endl << std::endl <<
	"  example squid ACL:" << std::endl <<
	"  external_acl_type type_comp_allow_map ttl=20 children=4 %SRC /path/to/group_ldap_acl -H ldaps://ldap.org -b cn=allow_computers,ou=group,dc=org" << std::endl <<
	"  acl COMP_ALLOW external type_comp_allow_map" << std::endl <<
	"  ..." << std::endl <<
	"  http_access deny !COMP_ALLOW" << std::endl << std::endl <<
	"  # for check %LOGIN need define proxy_auth above" << std::endl <<
	"  external_acl_type type_users_map ttl=20 children=10 %LOGIN /path/to/group_ldap_acl -H ldaps://ldap.org -b cn=allow_user,ou=group,dc=org" << std::endl <<
	"  acl USERS_ALLOW external type_users_map" << std::endl <<
	"  ..." << std::endl <<
	"  http_access allow USERS_ALLOW" << std::endl << std::endl << std::endl <<
	"  authorization file:" << std::endl <<
	"  login dn" << std::endl <<
	"  password" << std::endl << std::endl <<
        "Signals: " << std::endl <<
        "  SIGHUP - syslog debug on/off" << std::endl;
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

std::list<std::string> split(const std::string & str, int sep)
{
    std::list<std::string> list;
    size_t pos1 = 0;
    size_t pos2 = std::string::npos;

    while(pos1 < str.size() &&
        std::string::npos != (pos2 = str.find(sep, pos1)))
    {
        list.push_back(str.substr(pos1, pos2 - pos1));
        pos1 = pos2 + 1;
    }

    // tail
    if(pos1 < str.size())
        list.push_back(str.substr(pos1, str.size() - pos1));

    return list;
}

void lower(std::string & str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

static bool logging = false;

void signalHandler(int sig)
{
    if(sig == SIGHUP)
    {
        if(logging)
        {
            logging = false;
            syslog(LOG_INFO, "[%d] logging disabled", getpid());
        }
        else
        {
            logging = true;
            syslog(LOG_INFO, "[%d] logging enabled", getpid());
        }
    }
}

int main(int argc, char **argv)
{
    int c;

    std::string uri, group_dn, login, passwd, authfile;
    std::string attr("memberUid");
    std::list<std::string> URIs;
    bool insensitive = false;

    while((c = getopt(argc, argv, "H:b:f:a:idh")) != -1)
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

            case 'd':
		logging = true;
                break;

            case 'h':
                help(argv[0]);
                return 0;

           default: break;
       }
    }

    if(uri.empty() || group_dn.empty())
    {
        help(argv[0]);
        return 0;
    }
    else
    {
	URIs = split(uri, ',');
    }

    Ldap::Pools pools;
    if(authfile.size()) parse(authfile, login, passwd);

    for(auto it = URIs.begin(); it != URIs.end(); ++it)
    {
	pools.AddServer(Ldap::Info(*it));

	if(pools.back().Connect(*it) && pools.back().Bind(login, passwd))
	    break;

	std::cerr << "URI: " << *it << ", error: " <<  pools.back().Message() << std::endl;
    }

    if(0 == std::count_if(pools.begin(), pools.end(), std::mem_fun_ref(&Ldap::Server::IsConnected)))
    {
	std::cerr << "LDAP servers not connected" << std::endl;
        return 1;
    }

    signal(SIGHUP, signalHandler);
    openlog("group_ldap_acl", 0, LOG_DAEMON);

    if(logging)
    {
    	syslog(LOG_INFO, "running version %s, cldap: %d", VERSION, Ldap::getVersion());

        const Ldap::ListEntries & result = pools.Search(group_dn, Ldap::ScopeBase);
        if(result.size())
        {
	    std::list<std::string> values = result.front().GetStringList(attr);

    	    syslog(LOG_DEBUG, "search dn: %s", group_dn.c_str());
    	    syslog(LOG_DEBUG, "result count: %ld", result.size());
    	    syslog(LOG_DEBUG, "values count: %ld", values.size());

    	    for(auto it = values.begin(); it != values.end(); ++it)
    		syslog(LOG_DEBUG, " - value: %s", (*it).c_str());
	}
    }

    std::string stream;
    pid_t pid = getpid();

    struct in_addr in;
    struct hostent *hp;

    while(std::cin >> stream)
    {
        syslog(LOG_INFO, "[%d] request: %s", pid, stream.c_str());

	const Ldap::ListEntries & result = pools.Search(group_dn, Ldap::ScopeBase);
	if(result.size())
	{
    	    std::list<std::string> values = result.front().GetStringList(attr);

    	    if(insensitive)
    	    {
        	lower(stream);
        	std::for_each(values.begin(), values.end(), lower);
	    }

    	    if(values.end() != std::find(values.begin(), values.end(), stream))
            {
                syslog(LOG_DEBUG, "[%d] reply OK, value: `%s'", pid, stream.c_str());
                SEND_OK("");
    	    }
            else
    	    // possible ip address (3 dots)
    	    if(3 == std::count(stream.begin(), stream.end(), '.') &&
            	inet_aton(stream.c_str(), &in) &&
            	(hp = gethostbyaddr((char *) &in.s_addr, sizeof(in.s_addr), AF_INET)))
    	    {
            	std::string hostname(hp->h_name);
    		if(insensitive) lower(hostname);

            	if(values.end() != std::find(values.begin(), values.end(), hostname))
                {
                    syslog(LOG_DEBUG, "[%d] reply OK, hostname: `%s'", pid, hostname.c_str());
                    SEND_OK("");
            	}
                else
                {
                    if(logging)
                    {
                        syslog(LOG_DEBUG, "[%d] reply ERR, hostname: `%s'", pid, hostname.c_str());
                        SEND_ERR("");
                    }
                    else
                        SEND_ERR("not found, hostname: `" << hostname << "'");
                }
    	    }
    	    else
            {
                if(logging)
                {
                    syslog(LOG_DEBUG, "[%d] reply ERR, value: `%s'", pid, stream.c_str());
                    SEND_ERR("");
                }
                else
                    SEND_ERR("not found, value: `" << stream << "'");
            }
	}
    	else
        {
            if(logging)
            {
                syslog(LOG_DEBUG, "[%d] reply ERR, search empty, dn: %s", pid, group_dn.c_str());
                SEND_ERR("");
            }
            else
                SEND_ERR("search empty, dn: " << group_dn);
        }

        std::cout.flush();
    }

    closelog();
    return EXIT_SUCCESS;
}
