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

#ifndef CLDAP_ENTRY_H
#define CLDAP_ENTRY_H

#include "cldap_types.h"

namespace Ldap
{
    class Mod;
    class Server;

    class Entry
    {
	public:
	    Entry(const std::string & dn = "");
	    Entry(const Entry & entry);
	    ~Entry();

	    Entry & operator= (const Entry & entry);

	    void DN(const std::string & dn);
	    const std::string & DN(void) const;

    	    void Replace(const std::string & attr, const std::string & value);
    	    void Replace(const std::string & attr, const std::vector<char> & value);
    	    void Replace(const std::string & attr, const std::list<std::string> & values);

    	    void Delete(const std::string & attr, const std::string & value = "");
    	    void Delete(const std::string & attr, const std::vector<char> & value);
    	    void Delete(const std::string & attr, const std::list<std::string> & values);

    	    void Add(const Mod & mod);
    	    void Add(const std::string & attr, const std::string & value);
    	    void Add(const std::string & attr, const std::vector<char> & value);
    	    void Add(const std::string & attr, const std::list<std::string> & values);

	    void Modify(const LDAPMod **ldapmods);

	    const Mod* Exists(const std::string & attr) const;
	    const Mod* Exists(const std::string & attr, const std::string & val) const;
	    const Mod* Exists(const std::string & attr, const std::vector<char> & val) const;

            void Dump(std::ostream & stream = std::cout) const;

            void GetValue(const std::string & attr, std::string & result) const;
            void GetValue(const std::string & attr, std::vector<char> & result) const;

            void GetValues(const std::string & attr, std::list<std::string> & result) const;
            void GetValues(const std::string & attr, std::list< std::vector<char> > & result) const;

    	    LDAPMod** c_LDAPMod(void);

	private:
	    Mod *		Find(const std::string & attr, actions_t action, bool binary = false);

	    std::string		entry_dn;
	    std::vector<Mod *>	entry_ldapmods;
    };
};

#endif
