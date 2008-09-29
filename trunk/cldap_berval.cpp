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

Ldap::Berval::Berval()
{
    bv_len = 0;
    bv_val = NULL;
}

Ldap::Berval::~Berval()
{
    if(bv_len && bv_val) delete [] bv_val;
}

Ldap::Berval::Berval(const std::vector<char> & v)
{
    bv_len = v.size();
    bv_val = NULL;
    
    if(bv_len)
    {
	bv_val = new char[bv_len];
	memcpy(bv_val, &v[0], bv_len);
    }
}

Ldap::Berval::Berval(const berval & b)
{
    bv_len = b.bv_len;
    bv_val = NULL;
    
    if(bv_len)
    {
	bv_val = new char[bv_len];
	memcpy(bv_val, b.bv_val, bv_len);
    }
}

Ldap::Berval::Berval(int l, const char *v)
{
    bv_len = l;
    bv_val = NULL;

    if(l && v)
    {
	bv_val = new char[bv_len];
	memcpy(bv_val, v, bv_len);
    }
}

Ldap::Berval & Ldap::Berval::operator= (const std::vector<char> & v)
{
    if(bv_len && bv_val) delete [] bv_val;

    bv_len = v.size();
    bv_val = NULL;
    
    if(bv_len)
    {
	bv_val = new char[bv_len];
	memcpy(bv_val, &v[0], bv_len);
    }

    return *this;
}

Ldap::Berval & Ldap::Berval::operator= (const berval & b)
{
    if(bv_len && bv_val) delete [] bv_val;

    bv_len = b.bv_len;
    bv_val = NULL;
    
    if(bv_len)
    {
	bv_val = new char[bv_len];
	memcpy(bv_val, b.bv_val, bv_len);
    }

    return *this;
}

bool Ldap::Berval::operator== (const Berval & b)
{
    return bv_len == b.bv_len && 0 == memcmp(bv_val, b.bv_val, bv_len);
}

bool Ldap::Berval::operator== (const std::vector<char> & v)
{
    return bv_len == v.size() && 0 == memcmp(bv_val, &v[0], bv_len);
}

bool Ldap::Berval::operator== (const std::string & s)
{
    return 0 == strncmp(bv_val, s.c_str(), bv_len);
}

std::ostream & Ldap::operator<< (std::ostream & os, const Berval & ber)
{
    os << "[binary data]";

    return os;
}
