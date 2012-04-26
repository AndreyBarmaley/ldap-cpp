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

#ifndef CLDAP_SERVER_H
#define CLDAP_SERVER_H

#include "cldap_types.h"

namespace Ldap
{
    class Server
    {
	public:
            Server();
            Server(const std::string & uri, bool ssl = false);
            ~Server();

            const std::string & URI(void) const;
            const std::string & BindDN(void) const;

            bool Connect(const std::string & uri = "", bool ssl = false);
            void Disconnect(void);

            bool Bind(void);
            bool Bind(const std::string & bind_dn, const std::string & bind_pw);
            void Unbind(void);

            bool Ping(void) const;

	    Entries Search(const std::string & base, scope_t scope = BASE, const std::string & filter = "", const Attrs* = NULL);

            bool Add(const Entry & entry);
            bool Modify(const Entry & entry);
	    bool Compare(const std::string & attr, const std::string & val) const;
	    bool Delete(const std::string & dn);
	    bool ModDN(const std::string & dn, const std::string & newdn);

            int Error(void) const;
            const char* Message(void) const;

	protected:
	    void	CreateURI(const std::string & uri, bool ssl);

            std::string			ldap_uri;
            std::string			ldap_bind_dn;
            std::string			ldap_bind_pw;

            LDAP*			ldap_object;
	    int				ldap_errno;
    };

    std::ostream & operator<< (std::ostream &, const Entries &);
};

#endif
