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

#include "cldap_berval.h"
#include "cldap_mod.h"

Ldap::Mod::Mod()
{
    mod_op = 0;
    mod_type = NULL;
    mod_bvalues = NULL;
}

Ldap::Mod::Mod(const LDAPMod & ldapmod)
{
    mod_op = ldapmod.mod_op;

    type = std::string(ldapmod.mod_type);
    mod_type = const_cast<char *>(type.c_str());

    if(ldapmod.mod_op & LDAP_MOD_BVALUES)
    {
	const berval *ber = ldapmod.mod_bvalues[0];

	while(ber)
	{
	    bvals.push_back(new Berval(*ber));

	    ++ber;
	}

	mod_bvalues = bvals.size() ? reinterpret_cast<berval **>(&bvals[0]) : NULL;
    }
    else
    {
	const char *str = ldapmod.mod_values[0];
	
	while(str)
	{
	    strvals.push_back(strdup(str));

	    ++str;
	}

	mod_values = strvals.size() ? &strvals[0] : NULL;
    }
}

Ldap::Mod::Mod(const std::string & attr, const std::string & val, const actions_t action) : type(attr)
{
    mod_op = action;
    mod_type = const_cast<char *>(type.c_str());

    Append(val);
}

Ldap::Mod::Mod(const std::string & attr, const std::vector<char> & val, const actions_t action) : type(attr)
{
    mod_op = LDAP_MOD_BVALUES | action;
    mod_type = const_cast<char *>(type.c_str());

    Append(val);
}

Ldap::Mod::Mod(const std::string & attr, const std::list<std::string> & vals, const actions_t action) : type(attr)
{
    mod_op = action;
    mod_type = const_cast<char *>(type.c_str());

    Append(vals);
}

Ldap::Mod::~Mod()
{
    Clear();
}

Ldap::Mod & Ldap::Mod::operator= (const LDAPMod & ldapmod)
{
    Clear();

    mod_op = ldapmod.mod_op;

    type = std::string(ldapmod.mod_type);
    mod_type = const_cast<char *>(type.c_str());

    if(ldapmod.mod_op & LDAP_MOD_BVALUES)
    {
	const berval *ber = ldapmod.mod_bvalues[0];

	while(ber)
	{
	    bvals.push_back(new Berval(*ber));

	    ++ber;
	}

	mod_bvalues = bvals.size() ? reinterpret_cast<berval **>(&bvals[0]) : NULL;
    }
    else
    {
	const char *str = ldapmod.mod_values[0];
	
	while(str)
	{
	    strvals.push_back(strdup(str));

	    ++str;
	}

	mod_values = strvals.size() ? &strvals[0] : NULL;
    }
    
    return *this;
}

bool Ldap::Mod::Binary(void)
{
    return mod_op & LDAP_MOD_BVALUES;
}

void Ldap::Mod::Clear(void)
{
    mod_type = NULL;
    mod_bvalues = NULL;

    type.clear();

    if(LDAP_MOD_BVALUES & mod_op)
    {
	std::vector<Berval *>::const_iterator it1 = bvals.begin();
	std::vector<Berval *>::const_iterator it2 = bvals.end();

	for(; it1 != it2; ++it1) if(*it1) delete *it1;
    }
    else
    {
	std::vector<char *>::const_iterator it1 = strvals.begin();
	std::vector<char *>::const_iterator it2 = strvals.end();

	// free becose used strdup
	for(; it1 != it2; ++it1) if(*it1) free(*it1);
    }

    mod_op = 0;
}

bool Ldap::Mod::Append(const std::string & val)
{
    if(val.empty() || mod_op & LDAP_MOD_BVALUES) return false;

    strvals.push_back(strdup(val.c_str()));

    mod_values = &strvals[0];

    return true;
}

bool Ldap::Mod::Append(const std::vector<char> & val)
{
    if(val.empty() || !(mod_op & LDAP_MOD_BVALUES)) return false;

    bvals.push_back(new Berval(val));

    mod_bvalues = reinterpret_cast<berval **>(&bvals[0]);

    return true;
}

bool Ldap::Mod::Append(const std::list<std::string> & val)
{
    if(val.empty() || mod_op & LDAP_MOD_BVALUES) return false;

    std::list<std::string>::const_iterator it1 = val.begin();
    std::list<std::string>::const_iterator it2 = val.end();
    
    for(; it1 != it2; ++it1)
	strvals.push_back(strdup((*it1).c_str()));

    mod_values = &strvals[0];

    return true;
}

bool Ldap::Mod::Exists(const std::string & val)
{
    if(val.empty() || mod_op & LDAP_MOD_BVALUES) return false;

    return strvals.end() != std::find_if(strvals.begin(), strvals.end(), std::not1(std::bind2nd(std::ptr_fun(strcmp), val.c_str())));
}

bool Ldap::Mod::Exists(const std::vector<char> & val)
{
    if(val.empty() || !(mod_op & LDAP_MOD_BVALUES)) return false;

    std::vector<Berval *>::const_iterator it1 = bvals.begin();
    std::vector<Berval *>::const_iterator it2 = bvals.end();

    for(; it1 != it2; ++it1)
    	if(val == **it1) return true;

    return false;
}

Ldap::actions_t Ldap::Mod::Action(void)
{
    if(mod_op & LDAP_MOD_ADD) return ADD;
    else
    if(mod_op & LDAP_MOD_DELETE) return DELETE;
    else
    if(mod_op & LDAP_MOD_REPLACE) return REPLACE;

    return NONE;
}

const std::string & Ldap::Mod::Attr(void)
{
    return type;
}

void Ldap::Mod::Dump(std::ostream & stream) const
{
    if(mod_op & LDAP_MOD_BVALUES)
    {
	std::vector<Berval *>::const_iterator it1 = bvals.begin();
	std::vector<Berval *>::const_iterator it2 = bvals.end();

	for(; it1 != it2; ++it1) stream << type << ": [binary data]" << std::endl;
    }
    else
    {
	std::vector<char *>::const_iterator it1 = strvals.begin();
	std::vector<char *>::const_iterator it2 = strvals.end();

	for(; it1 != it2; ++it1) stream << type << ": " << *it1 << std::endl;
    }
}

const std::vector<Ldap::Berval *> & Ldap::Mod::BinaryValues(void) const
{
    return bvals;
}

const std::vector<char *> & Ldap::Mod::StringValues(void) const
{
    return strvals;
}

void Ldap::Mod::GetValue(std::string & result) const
{
    if(mod_op & LDAP_MOD_BVALUES || strvals.empty()) return;
    
    result.clear();
    
    if(strvals[0]) result = strvals[0];
}

void Ldap::Mod::GetValue(std::vector<char> & result) const
{
    if(!(mod_op & LDAP_MOD_BVALUES) || bvals.empty()) return;

    result.clear();

    if(bvals[0]) result = *bvals[0];
}

void Ldap::Mod::GetValues(std::list<std::string> & result) const
{
    if(mod_op & LDAP_MOD_BVALUES || strvals.empty()) return;
    
    result.clear();
    
    std::vector<char *>::const_iterator it1 = strvals.begin();
    std::vector<char *>::const_iterator it2 = strvals.end();
    
    for(; it1 != it2; ++it1) if(*it1) result.push_back(*it1);
}

void Ldap::Mod::GetValues(std::list< std::vector<char> > & result) const
{
    if(!(mod_op & LDAP_MOD_BVALUES) || bvals.empty()) return;

    result.clear();

    std::vector<Berval *>::const_iterator it1 = bvals.begin();
    std::vector<Berval *>::const_iterator it2 = bvals.end();

    for(; it1 != it2; ++it1) if(*it1) result.push_back(**it1);
}
