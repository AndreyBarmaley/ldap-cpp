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
    std::cout << "ldap connect: " <<  ldap.Message() << std::endl;

    bool success = false;
    success = ldap.Bind(bind_dn, bind_pw);

    std::cout << "ldap bind: " <<  ldap.Message() << std::endl;
    if(! success) return 1;

    const std::string & test_ou = "cldap_test_ou";
    const std::string object_dn("ou=" + test_ou + "," + bdn);
    Ldap::Entry entry(object_dn);

    entry.Append(Ldap::ADD, "objectClass", "top");
    entry.Append(Ldap::ADD, "objectClass", "organizationalUnit");
    entry.Append(Ldap::ADD, "ou", test_ou);

    //std::list<std::string> vals;
    //vals.push_back("this test organizational unit block");
    //vals.push_back("addons description line 2");
    //vals.push_back("addons description line 3");

    entry.Append(Ldap::ADD, "description", "vals");
    std::cout << std::endl << "entry dump: " <<  std::endl << entry << std::endl << std::endl;

    // update
    success = ldap.Add(entry);
    std::cout << "ldap add: " <<  ldap.Message() << std::endl;
    if(success)
    {
	Ldap::Entry entry2(entry.DN());
	entry2.Append(Ldap::REPLACE, "description", "vals ssssss");
	success = ldap.Modify(entry2);
	std::cout << "ldap modify: " <<  ldap.Message() << std::endl;
	if(! success) return 3;
    }

    // search
    Ldap::Entries result = ldap.Search(object_dn, Ldap::BASE);
    std::cout << std::endl << "ldap search: " << object_dn << std::endl << "found: " << result.size() << " entries." << std::endl << std::endl;
    if(result.size())
    {
	std::cout << result;

	// delete
	success = ldap.Delete(object_dn);
	std::cout << "ldap delete: " << ldap.Message() << std::endl << std::endl;
    }

    return 0;
}
