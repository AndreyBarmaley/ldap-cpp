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

Ldap::Berval::Berval(const std::vector<char> & v) : std::vector<char>(v)
{
    bv_len = size();
    bv_val = bv_len ? &at(0) : NULL;
}

Ldap::Berval::Berval(const berval & b)
{
    bv_len = 0;
    bv_val = NULL;

    if(b.bv_len && b.bv_val)
    {
	assign(b.bv_val, &b.bv_val[b.bv_len - 1]);

	bv_len = size();
	bv_val = &at(0);
    }
}

Ldap::Berval::Berval(int l, char *v)
{
    bv_len = 0;
    bv_val = NULL;

    if(l && v)
    {
	assign(v, &v[l - 1]);

	bv_len = size();
	bv_val = &at(0);
    }
}

Ldap::Berval & Ldap::Berval::operator= (const std::vector<char> & v)
{
    clear();

    assign(v.begin(), v.end());

    bv_len = size();
    bv_val = bv_len ? &at(0) : NULL;

    return *this;
}

Ldap::Berval & Ldap::Berval::operator= (const berval & b)
{
    clear();

    bv_len = 0;
    bv_val = NULL;

    if(b.bv_len && b.bv_val)
    {
	assign(b.bv_val, &b.bv_val[b.bv_len - 1]);

	bv_len = size();
	bv_val = &at(0);
    }

    return *this;
}

Ldap::Berval & Ldap::Berval::operator= (const Ldap::Berval & v)
{
    clear();

    assign(v.begin(), v.end());

    bv_len = size();
    bv_val = bv_len ? &at(0) : NULL;

    return *this;
}
