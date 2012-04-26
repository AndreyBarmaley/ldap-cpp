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

#include <cstring>
#include <iomanip>
#include <functional>
#include <algorithm>
#include "cldap_mod.h"

char* StrDup(const char* str)
{
    size_t len = strlen(str);
    char*  res = new char [len + 1];
    std::copy(str, str + len, res);
    res[len] = 0;
    return res;
}

struct Berval : berval
{
    Berval()
    {
	bv_len = 0;
	bv_val = NULL;
    }

    Berval(const char* val, size_t len)
    {
	bv_len = 0;
	bv_val = NULL;

	Assign(val, len);
    }

    Berval(const berval & ber)
    {
	bv_len = 0;
	bv_val = NULL;

	Assign(ber.bv_val, ber.bv_len);
    }

    Berval & operator= (const berval & ber)
    {
	if(&ber != this)
	    Assign(ber.bv_val, ber.bv_len);

	return *this;
    }

    ~Berval()
    {
	Clear();
    }

    void Clear(void)
    {
	if(bv_val) delete [] bv_val;

	bv_len = 0;
	bv_val = NULL;
    }

    void Assign(const char* val, size_t len)
    {
	Clear();

	if(len && val)
	{
	    bv_len = len;
	    bv_val = new char [len];
	    std::memcpy(bv_val, val, len);
	}
    }
};

Ldap::Mod::Mod(int op, const char* type)
{
    mod_op = op;
    mod_type = type ? StrDup(type) : NULL;
    mod_bvalues = NULL;

    mod_vals_size = 0;
}

Ldap::Mod::~Mod()
{
    Clear();
}

void Ldap::Mod::Clear(void)
{
    if(mod_bvalues)
    {
	if(mod_op & LDAP_MOD_BVALUES)
	{
	    for(berval** bval = mod_bvalues; bval && *bval; ++bval) delete static_cast<Berval*>(*bval);
	    delete [] mod_bvalues;
	    mod_bvalues = NULL;
	}
	else
	{
	    for(char** val = mod_values; val && *val; ++val) delete [] *val;
	    delete [] mod_values;
	    mod_values = NULL;
	}
    }

    if(mod_type)
    {
	delete [] mod_type;
	mod_type = NULL;
    }

    mod_op = 0;
}

bool Ldap::Mod::IsOperation(int op) const
{
    return (mod_op & LDAP_MOD_OP) == op;
}

bool Ldap::Mod::IsType(const char* str) const
{
    return 0 == std::strcmp(mod_type, str);
}

void Ldap::Mod::Append(const char* str)
{
    if(mod_values)
    {
	// add
	char** itbeg = mod_values;
	char** itend = mod_values + mod_vals_size - 1; // skip last: always is NULL
	char** itcur = std::find(itbeg, itend, static_cast<char*>(0));

	if(itcur != itend)
	    *itcur = StrDup(str);
	else
	{
	    // resize
	    size_t new_vals_size = mod_vals_size * 2;
	    char** new_values = new char* [new_vals_size];
	    std::memset(new_values, 0, sizeof(char*) * new_vals_size);
	    std::copy(itbeg, itend, new_values);
	    delete [] mod_values;
	    mod_values = new_values;
	    mod_values[mod_vals_size - 1] = StrDup(str);
	    mod_vals_size = new_vals_size;
	}
    }
    else
    {
	// add
	mod_vals_size = 4;
	mod_values = new char* [mod_vals_size];
	std::memset(mod_values, 0, sizeof(char*) * mod_vals_size);
	mod_values[0] = StrDup(str);
    }
}

void Ldap::Mod::Append(const char* val, size_t len)
{
    if(mod_bvalues)
    {
	// add
	berval** itbeg = mod_bvalues;
	berval** itend = mod_bvalues + mod_vals_size - 1; // skip last: always is NULL
	berval** itcur = std::find(itbeg, itend, static_cast<berval*>(0));

	if(itcur != itend)
	    *itcur = new Berval(val, len);
	else
	{
	    // resize
	    size_t new_vals_size = mod_vals_size * 2;
	    berval** new_bvalues = new berval* [new_vals_size];
	    std::memset(new_bvalues, 0, sizeof(berval*) * new_vals_size);
	    std::copy(itbeg, itend, new_bvalues);
	    delete [] mod_bvalues;
	    mod_bvalues = new_bvalues;
	    mod_bvalues[mod_vals_size - 1] = new Berval(val, len);
	    mod_vals_size = new_vals_size;
	}
    }
    else
    {
	// add
	mod_vals_size = 4;
	mod_bvalues = new berval* [mod_vals_size];
	std::memset(mod_bvalues, 0, sizeof(berval*) * mod_vals_size);
	mod_bvalues[0] = new Berval(val, len);

	// set binary
	mod_op |= LDAP_MOD_BVALUES;
    }
}

const char* const* Ldap::Mod::GetStrValues(void) const
{
    return mod_op & LDAP_MOD_BVALUES ? NULL : mod_values;
}

const berval* const* Ldap::Mod::GetBinValues(void) const
{
    return mod_op & LDAP_MOD_BVALUES ? mod_bvalues : NULL;
}

std::ostream & Ldap::operator<< (std::ostream & os, const Mod & mod)
{
    if(mod.mod_bvalues)
    {
	if(mod.mod_op & LDAP_MOD_BVALUES)
	    for(berval** bval = mod.mod_bvalues; bval && *bval; ++bval)
	    {
		os << mod.mod_type << ": ";
 		for(size_t ii = 0; ii < (*bval)->bv_len; ++ii)
		    os << (*bval)->bv_val[ii];
//			os << " 0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>((*bval)->bv_val[ii]);
		os << std::endl;
	    }
	else
	    for(char** val = mod.mod_values; val && *val; ++val)
		os << mod.mod_type << ": " << *val << std::endl;
    }
    else
	os << mod.mod_type << ":" << std::endl;

    return os;
}

