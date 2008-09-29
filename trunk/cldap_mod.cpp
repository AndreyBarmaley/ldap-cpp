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

#include <algorithm>
#include "cldap_berval.h"
#include "cldap_mod.h"

char* StrDup(const char *str, unsigned int size)
{
    if(! str) return NULL;
    char *dup = new char [size + 1];
    strcpy(dup, str);
    dup[size] = '\0';

    return dup;
}

Ldap::Mod::Mod()
{
    mod_op = 0;
    mod_type = NULL;
    mod_bvalues = NULL;
}

Ldap::Mod::Mod(const Mod & mod)
{
    mod_op = mod.mod_op;
    mod_type = StrDup(mod.mod_type, strlen(mod.mod_type));
    mod_bvalues = NULL;

    if(mod_op & LDAP_MOD_BVALUES)
    {
	const unsigned int size = BervalSize(mod.mod_bvalues);
	berval** bvalues = mod.mod_bvalues;
        for(unsigned int ii = 0; ii < size; ++ii, ++bvalues) Append((*bvalues)->bv_val, (*bvalues)->bv_len);
    }
    else
    {
	const unsigned int size = BervalSize(mod.mod_values);
	char** values = mod.mod_values;
	for(unsigned int ii = 0; ii < size; ++ii, ++values) Append(*values, strlen(*values));
    }
}

Ldap::Mod::Mod(const LDAPMod & ldapmod)
{
    mod_op = ldapmod.mod_op;
    mod_type = StrDup(ldapmod.mod_type, strlen(ldapmod.mod_type));
    mod_bvalues = NULL;

    if(mod_op & LDAP_MOD_BVALUES)
    {
	const unsigned int size = BervalSize(ldapmod.mod_bvalues);
	berval** bvalues = ldapmod.mod_bvalues;
        for(unsigned int ii = 0; ii < size; ++ii, ++bvalues) Append((*bvalues)->bv_val, (*bvalues)->bv_len);
    }
    else
    {
	const unsigned int size = BervalSize(ldapmod.mod_values);
	char** values = ldapmod.mod_values;
	for(unsigned int ii = 0; ii < size; ++ii, ++values) Append(*values, strlen(*values));
    }
}

Ldap::Mod::Mod(const std::string & attr, const actions_t action, bool binary)
{
    mod_op = binary ? LDAP_MOD_BVALUES | action : action;
    mod_type = StrDup(attr.c_str(), attr.size());
    mod_bvalues = NULL;
}

Ldap::Mod::Mod(const std::string & attr, const std::string & val, const actions_t action)
{
    mod_op = action;
    mod_type = StrDup(attr.c_str(), attr.size());
    mod_bvalues = NULL;

    Append(val);
}

Ldap::Mod::Mod(const std::string & attr, const std::vector<char> & val, const actions_t action)
{
    mod_op = LDAP_MOD_BVALUES | action;
    mod_type = StrDup(attr.c_str(), attr.size());
    mod_bvalues = NULL;

    Append(val);
}

Ldap::Mod::Mod(const std::string & attr, const std::list<std::string> & vals, const actions_t action)
{
    mod_op = action;
    mod_type = StrDup(attr.c_str(), attr.size());
    mod_bvalues = NULL;

    Append(vals);
}

Ldap::Mod::~Mod()
{
    Clear();
}

void Ldap::Mod::Append(const char* val, const unsigned int len)
{
    if(NULL == val || 0 == len) return;

    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    const unsigned int old_size = BervalSize(mod_bvalues);
	    berval** new_bvalues = new berval* [old_size + 2];
	    memcpy(new_bvalues, mod_bvalues, old_size * sizeof(berval*));
	    new_bvalues[old_size] = new Berval(len, val);
	    new_bvalues[old_size + 1] = NULL;
	    delete [] mod_bvalues;
	    mod_bvalues = new_bvalues;
	}
	else
	{
	    mod_bvalues = new berval* [2];
	    mod_bvalues[0] = new Berval(len, val);
	    mod_bvalues[1] = NULL;
	}
    }
    else
    {
	if(mod_values)
	{
	    const unsigned int old_size = BervalSize(mod_values);
	    char** new_values = new char* [old_size + 2];
	    memcpy(new_values, mod_values, old_size * sizeof(char*));
	    new_values[old_size] = StrDup(val, len);
	    new_values[old_size + 1] = NULL;
	    delete [] mod_values;
	    mod_values = new_values;
	}
	else
	{
	    mod_values = new char* [2];
	    mod_values[0] = StrDup(val, len);
	    mod_values[1] = NULL;
	}
    }
}

bool Ldap::Mod::Append(const std::string & val)
{
    if(val.empty()) return false;

    Append(val.c_str(), val.size());

    return true;
}

bool Ldap::Mod::Append(const std::vector<char> & val)
{
    if(val.empty()) return false;

    Append(&val[0], val.size());

    return true;
}

bool Ldap::Mod::Append(const std::list<std::string> & val)
{
    if(val.empty()) return false;

    std::list<std::string>::const_iterator it1 = val.begin();
    std::list<std::string>::const_iterator it2 = val.end();

    for(; it1 != it2; ++it1) Append(*it1);

    return true;
}

Ldap::Mod & Ldap::Mod::operator= (const LDAPMod & ldapmod)
{
    Clear();

    mod_op = ldapmod.mod_op;
    mod_type = StrDup(ldapmod.mod_type, strlen(ldapmod.mod_type));

    if(mod_op & LDAP_MOD_BVALUES)
    {
	const unsigned int size = BervalSize(ldapmod.mod_bvalues);
	berval** bvalues = ldapmod.mod_bvalues;
        for(unsigned int ii = 0; ii < size; ++ii, ++bvalues) Append((*bvalues)->bv_val, (*bvalues)->bv_len);
    }
    else
    {
	const unsigned int size = BervalSize(ldapmod.mod_values);
	char** values = ldapmod.mod_values;
	for(unsigned int ii = 0; ii < size; ++ii, ++values) Append(*values, strlen(*values));
    }

    return *this;
}

Ldap::Mod & Ldap::Mod::operator= (const Mod & mod)
{
    Clear();

    mod_op = mod.mod_op;
    mod_type = StrDup(mod.mod_type, strlen(mod.mod_type));

    if(mod_op & LDAP_MOD_BVALUES)
    {
	const unsigned int size = BervalSize(mod.mod_bvalues);
	berval** bvalues = mod.mod_bvalues;
        for(unsigned int ii = 0; ii < size; ++ii, ++bvalues) Append((*bvalues)->bv_val, (*bvalues)->bv_len);
    }
    else
    {
	const unsigned int size = BervalSize(mod.mod_values);
	char** values = mod.mod_values;
	for(unsigned int ii = 0; ii < size; ++ii, ++values) Append(*values, strlen(*values));
    }

    return *this;
}

bool Ldap::Mod::Binary(void)
{
    return mod_op & LDAP_MOD_BVALUES;
}

bool Ldap::Mod::Exists(const std::string & val)
{
    if(val.empty()) return false;

    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;

	    while(*bvalues)
	    {
		if(static_cast<Berval>(**bvalues) == val) return true;
		++bvalues;
	    }
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;

	    while(*values)
	    {
		if(strlen(*values) == val.size() && 0 == strcmp((*values), val.c_str())) return true;
		++values;
	    }
	}
    }

    return false;
}

bool Ldap::Mod::Exists(const std::vector<char> & val)
{
    if(val.empty()) return false;

    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;

	    while(*bvalues)
	    {
		if(static_cast<Berval>(**bvalues) == val) return true;
		++bvalues;
	    }
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;

	    while(*values)
	    {
		if(strlen(*values) == val.size() && 0 == memcmp((*values), &val[0], val.size())) return true;
		++values;
	    }
	}
    }

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

void Ldap::Mod::SetAction(const actions_t action)
{
    mod_op |= action;
}

const char* Ldap::Mod::Attr(void)
{
    return mod_type;
}

void Ldap::Mod::Dump(std::ostream & stream) const
{
    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;

	    while(*bvalues)
	    {
		stream << mod_type << ": " << static_cast<Berval>(**bvalues) << std::endl;
		++bvalues;
	    }
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;

	    while(*values)
	    {
		stream << mod_type << ": " << *values << std::endl;
		++values;
	    }
	}
    }
}

void Ldap::Mod::GetValue(std::string & result) const
{
    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues && *mod_bvalues) result.assign((*mod_bvalues)->bv_val, (*mod_bvalues)->bv_len);
    }
    else
    {
	if(mod_values && *mod_values) result.assign(*mod_values);
    }
}

void Ldap::Mod::GetValue(std::vector<char> & result) const
{
    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues && *mod_bvalues)	result.assign((*mod_bvalues)->bv_val, (*mod_bvalues)->bv_val + (*mod_bvalues)->bv_len);
    }
    else
    {
	if(mod_values && *mod_values) result.assign(*mod_values, *mod_values + strlen(*mod_values));
    }
}

void Ldap::Mod::GetValues(std::list<std::string> & result) const
{
    result.clear();

    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;

	    while(*bvalues)
	    {
		result.push_back(std::string((*bvalues)->bv_val, (*bvalues)->bv_len));
		++bvalues;
	    }
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;

	    while(*values)
	    {
		result.push_back(std::string(*values));
		++values;
	    }
	}
    }
}

void Ldap::Mod::GetValues(std::list< std::vector<char> > & result) const
{
    result.clear();

    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;

	    while(*bvalues)
	    {
		result.push_back(std::vector<char>((*bvalues)->bv_val, (*bvalues)->bv_val + (*bvalues)->bv_len));
		++bvalues;
	    }
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;

	    while(*values)
	    {
		result.push_back(std::vector<char>(*values, *values + strlen(*values)));
		++values;
	    }
	}
    }
}

unsigned int Ldap::Mod::BervalSize(const berval* const* ptr)
{
    unsigned int result = 0;
    
    if(ptr) while(*ptr++) ++result;

    return result;
}

unsigned int Ldap::Mod::BervalSize(const char* const* ptr)
{
    unsigned int result = 0;
    
    if(ptr) while(*ptr++) ++result;

    return result;
}

void Ldap::Mod::Clear(void)
{
    if(mod_op & LDAP_MOD_BVALUES)
    {
	if(mod_bvalues)
	{
	    berval** bvalues = mod_bvalues;
	    while(*bvalues){ delete static_cast<Berval*>(*bvalues); ++bvalues; }
	    delete [] mod_bvalues;
	    mod_bvalues = NULL;
	}
    }
    else
    {
	if(mod_values)
	{
	    char** values = mod_values;
	    while(*values){ delete [] (*values); ++values; }
	    delete [] mod_values;
	    mod_values = NULL;
	}
    }

    delete [] mod_type;

    mod_type = NULL;
    mod_op = 0;
}
