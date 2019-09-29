/***************************************************************************
 *   Copyright (C) 2012 by Andrey Afletdinov                               *
 *   afletdinov@gmail.com                                                  *
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

#include <iostream>
#include <cstring>

#include <unistd.h>
#include <pwd.h>

#include "cldap.h"

std::string StringReplace(const std::string & src, const char* pred, const std::string & val)
{
    std::string res = src;
    size_t pos = std::string::npos;
    while(std::string::npos != (pos = res.find(pred))) res.replace(pos, std::strlen(pred), val);
    return res;
}

int main(int argc, char **argv)
{
    int c;
    struct passwd profile(*getpwuid(getuid()));

    std::string uri;
    std::string group_dn;
    std::string filter("memberUid=$uid");
    bool debug = false;
    bool endline = false;

    while((c = getopt(argc, argv, "H:b:a:nd")) != -1)
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
        	filter = std::string(optarg);
        	break;

	    case 'n':
		endline = true;
		break;

	    case 'd':
		debug = true;
		break;

           default:
           break;
       }
    }

    if(uri.empty() || group_dn.empty())
    {
	std::cout << "Usage: " << std::string(argv[0]) << " [OPTIONS]" << std::endl;
	std::cout << "    -H  LDAP URI" << std::endl;
	std::cout << "    -b  LDAP Base group DN" << std::endl;
	std::cout << "    -f  filter, defaults: memberUid=$uid" << std::endl;
	std::cout << "    -n  delimiter is \\n" << std::endl;

	return 0;
    }

    Ldap::Server ldap;

    ldap.Connect(uri);

    if(ldap.Error())
    {
	std::cerr << "error: " <<  ldap.Message() << std::endl;
	return 1;
    }

    ldap.Bind();

    if(ldap.Error())
    {
	std::cerr << "error: " <<  ldap.Message() << std::endl;
	return 1;
    }

    filter = StringReplace(filter, "$uid", profile.pw_name);

    if(debug)
	std::cerr << "set filter: " <<  filter << std::endl;

    const Ldap::ListEntries result = ldap.Search(group_dn, Ldap::ScopeOne, filter);

    if(debug)
	std::cerr << "found results: " << result.size() << std::endl;

    if(result.size())
    {
	for(Ldap::ListEntries::const_iterator
	    it = result.begin(); it != result.end(); ++it)
	    if(endline)
		std::cout << (*it).GetStringValue("cn") << std::endl;
	    else
		std::cout << (*it).GetStringValue("cn") << " ";

        if(!endline) std::cout << std::endl;
    }

    return 0;
}
