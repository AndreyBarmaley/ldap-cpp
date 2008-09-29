/***************************************************************************
 *   Copyright (C) 2008 by Andrey Afletdinov                               *
 *   afletdinov@mail.dc.baikal.ru                                          *
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
    std::string bdn;
    std::string bind_dn;
    std::string bind_pw;

   while((c = getopt(argc, argv, "H:b:l:p:")) != -1)

       switch(c)
       {
	    case 'H':
		uri = std::string(optarg);
                break;

            case 'b':
        	bdn = std::string(optarg);
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

    if(uri.empty() || bdn.empty())
    {
	std::cout << "Usage: " << std::string(argv[0]) << " [OPTIONS]" << std::endl;
	std::cout << "    -H  LDAP URI" << std::endl;
	std::cout << "    -b  LDAP Base DN" << std::endl;
	std::cout << "    -l  LDAP Bind DN" << std::endl;
	std::cout << "    -p  LDAP Bind passwd" << std::endl;

	return 0;
    }

    Ldap::Server ldap;

    ldap.Connect(uri);
    std::cout << "connect: " <<  ldap.Message() << std::endl;

    ldap.Bind(bind_dn, bind_pw);
    std::cout << "bind: " <<  ldap.Message() << std::endl;

    const std::string & test_ou = "cldap_test_ou";
    const std::string object_dn("ou=" + test_ou + "," + bdn);
    Ldap::Entry entry(object_dn);

    entry.Add("objectClass", "top");
    entry.Add("objectClass", "organizationalUnit");
    entry.Add("ou", test_ou);

    //std::list<std::string> vals;
    //vals.push_back("this test organizational unit block");
    //vals.push_back("addons description line 2");
    //vals.push_back("addons description line 3");

    entry.Add("description", "vals");

    //entry.Dump();

    // update
    ldap.Add(entry);
    std::cout << "add: " <<  ldap.Message() << std::endl;

    Ldap::Entry entry2(entry.DN());
    entry2.Replace("description", "vals ssssss");
    ldap.Modify(entry2);
    std::cout << "modify: " <<  ldap.Message() << std::endl;

    // search
    Ldap::Entries result;
    ldap.Search(result, object_dn, Ldap::BASE);
    std::cout << std::endl << "search: " << object_dn << std::endl << "found: " << result.size() << " entries." << std::endl << std::endl;

    if(result.size())
    {
	Ldap::Entries::const_iterator it1 = result.begin();
	Ldap::Entries::const_iterator it2 = result.end();

	for(; it1 != it2; ++it1)
	{

	    std::cout << "dump result:" << std::endl;
	    (*it1).Dump();
	    std::cout << std::endl;
	}
    }

    // delete
    ldap.Delete(object_dn);
    std::cout << "delete: " << ldap.Message() << std::endl << std::endl;

    return 0;
}
