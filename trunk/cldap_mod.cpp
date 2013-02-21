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
#include <iterator>
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

#include <openssl/bio.h>
#include <openssl/evp.h>

namespace OpenSSL
{
    std::vector<char> EncodeBase64(const char* ptr, size_t size)
    {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());

        b64 = BIO_push(b64, bmem);
        BIO_write(b64, ptr, size);
        BIO_flush(b64);

        char* bptr = NULL;
        long  bsze = BIO_get_mem_data(b64, & bptr);

        std::vector<char> result(bsze + 1, 0);
        std::copy(bptr, bptr + bsze, result.begin());
        result.back() = '\n';

        BIO_free_all(b64);
        return result;
    };

    std::vector<char> DecodeBase64(const char* ptr, size_t size)
    {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf(const_cast<char*>(ptr), size);
        bmem = BIO_push(b64, bmem);

        std::vector<char> result(size, 0);
        BIO_read(bmem, & result[0], size);

        result.resize(std::distance(result.begin(),
                std::find_if(result.begin(), result.end(), std::bind2nd(std::equal_to<int>(), 0))));

        BIO_free_all(bmem);
        return result;
    };
}

std::ostream & Ldap::operator<< (std::ostream & os, const Mod & mod)
{
    const char* strbin = ";binary";

    if(mod.mod_bvalues)
    {
	if(mod.mod_op & LDAP_MOD_BVALUES)
	{
	    bool binary = std::strlen(mod.mod_type) > std::strlen(strbin) &&
		0 == std::strcmp(& mod.mod_type[std::strlen(mod.mod_type) - std::strlen(strbin)], strbin);

	    for(berval** bval = mod.mod_bvalues; bval && *bval; ++bval)
	    {
		os << mod.mod_type << ": ";

		if(! binary)
		{
		    char* bv_end = (*bval)->bv_val + (*bval)->bv_len - 1; // skip last '\0'
		    if(bv_end != std::find_if((*bval)->bv_val, bv_end, std::bind2nd(std::less<int>(), 20)))
			binary = true;
		}

		if(binary)
		{
		    std::vector<char> base64 = OpenSSL::EncodeBase64((*bval)->bv_val, (*bval)->bv_len);
		    std::copy(base64.begin(), base64.end(), std::ostream_iterator<char>(os, ""));
		}
		else
		{
		    std::copy((*bval)->bv_val, (*bval)->bv_val + (*bval)->bv_len, std::ostream_iterator<char>(os, ""));
		    os << std::endl;
		}
	    }
	}
	else
	    for(char** val = mod.mod_values; val && *val; ++val)
		os << mod.mod_type << ": " << *val << std::endl;
    }
    else
	os << mod.mod_type << ":" << std::endl;

    return os;
}

