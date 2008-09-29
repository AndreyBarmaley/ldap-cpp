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

#ifndef CLDAP_MOD_H
#define CLDAP_MOD_H

#include "cldap_types.h"

namespace Ldap
{
    //class Berval;
    class Mod : public LDAPMod
    {
    public:
	Mod();
	Mod(const Mod & mod);
	Mod(const LDAPMod & ldapmod);
	Mod(const std::string & attr, const actions_t action, bool binary = false);
	Mod(const std::string & attr, const std::string & vals, const actions_t action);
	Mod(const std::string & attr, const std::vector<char> & vals, const actions_t action);
	Mod(const std::string & attr, const std::list<std::string> & vals, const actions_t action);

	~Mod();

	Mod & operator= (const Mod & mod);
	Mod & operator= (const LDAPMod & ldapmod);

	bool Binary(void);
	bool Exists(const std::string & val);
	bool Exists(const std::vector<char> & val);

	const char* Attr(void);

	actions_t Action(void);
	void SetAction(const actions_t action);

	bool Append(const std::string & val);
	bool Append(const std::vector<char> & val);
	bool Append(const std::list<std::string> & val);
	void Append(const char* val, const unsigned int len);

	void Dump(std::ostream & stream = std::cout) const;

	void GetValue(std::string & result) const;
        void GetValue(std::vector<char> & result) const;

	void GetValues(std::list<std::string> & result) const;
        void GetValues(std::list< std::vector<char> > & result) const;

	static unsigned int BervalSize(const berval* const* ptr);
	static unsigned int BervalSize(const char* const* ptr);

    protected:
	void Clear(void);
    };
};

#endif
