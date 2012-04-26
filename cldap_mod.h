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

#ifndef CLDAP_MOD_H
#define CLDAP_MOD_H

#include "cldap_types.h"

namespace Ldap
{
    class Server;

    class Mod : protected LDAPMod
    {
    public:
	Mod(int, const char*);
	~Mod();

	void		Append(const char*);
	void		Append(const char*, size_t);

	void		Clear(void);

	bool		IsType(const char*) const;
	bool		IsOperation(int) const;

	const char* const*	GetStrValues(void) const;
	const berval* const*	GetBinValues(void) const;

    private:
    	friend class Server;
	friend std::ostream & operator<< (std::ostream &, const Mod &);

	size_t		mod_vals_size;
    };

    std::ostream & operator<< (std::ostream &, const Mod &);
};

#endif
