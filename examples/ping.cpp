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

    while((c = getopt(argc, argv, "H:")) != -1)

        switch(c)
        {
    	    case 'H':
                uri = std::string(optarg);
                break;

    	    default:
		break;
        }

    if(uri.empty())
    {
	std::cout << "Usage: " << std::string(argv[0]) << " [OPTIONS]" << std::endl << "    -H  LDAP URI" << std::endl;
	
	return 0;
    }

    Ldap::Server ldap;

    ldap.Connect(uri);

    std::cout << "ping: " << (ldap.Ping() ? "success" : "error") << std::endl;

    return 0;
}
