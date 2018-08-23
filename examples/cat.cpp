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
#include <unistd.h>

#include "cldap.h"

int main(int argc, char **argv)
{
    int c;

    std::string uri;
    std::string base_dn;
    std::string bind_dn;
    std::string bind_pw;
    bool base64_binary_only = false;

   while((c = getopt(argc, argv, "H:b:l:p:w")) != -1)

       switch(c)
       {
	    case 'w':
		base64_binary_only = true;
		break;

	    case 'H':
		uri = std::string(optarg);
                break;

            case 'b':
        	base_dn = std::string(optarg);
        	break;

            case 'l':
        	bind_dn = std::string(optarg);
        	break;

            case 'p':
        	bind_pw = std::string(optarg);
        	break;

           default:
           break;
       }

    if(uri.empty() || base_dn.empty())
    {
	std::cout << "Usage: " << std::string(argv[0]) << " [OPTIONS]" << std::endl;
	std::cout << "    -H  LDAP URI" << std::endl;
	std::cout << "    -b  LDAP Base DN" << std::endl;
	std::cout << "    -l  LDAP Bind DN" << std::endl;
	std::cout << "    -p  LDAP Bind passwd" << std::endl;
	std::cout << "    -w  (base64 only for binary data)" << std::endl;

	return 0;
    }

    Ldap::Server ldap;

    ldap.Connect(uri);
    if(! ldap.Bind(bind_dn, bind_pw)) return 1;

    Base64::SetBinaryOnly(base64_binary_only);

    Ldap::ListEntries result = ldap.Search(base_dn, Ldap::ScopeTree);
    if(! result.size())
    {
	std::cerr << "result empty" << std::endl;
	return 1;
    }

    std::cout << result;
    return 0;
}
