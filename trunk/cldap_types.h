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

#ifndef CLDAP_TYPES_H
#define CLDAP_TYPES_H

#include <string>
#include <list>
#include <vector>
#include <iostream>
#include <ldap.h>

namespace Ldap
{
    class Entry;

    typedef enum { NONE = 0, ADD = LDAP_MOD_ADD, DELETE = LDAP_MOD_DELETE, REPLACE = LDAP_MOD_REPLACE } actions_t;
    typedef enum { BASE = LDAP_SCOPE_BASE, ONE = LDAP_SCOPE_ONELEVEL, TREE = LDAP_SCOPE_SUBTREE } scope_t;

    typedef std::list<Entry>	Entries;
};

#endif
