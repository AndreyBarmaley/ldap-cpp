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

#include <algorithm>
#include <iterator>
#include "cldap_entry.h"
#include "cldap_server.h"

Ldap::Server::Server() : ldap_object(NULL), ldap_errno(0)
{
}

void Ldap::Server::CreateURI(const std::string & uri, bool ssl)
{
    const char* ldap1 = "ldaps://";
    const char* ldap2 = "ldap://";

    if(strlen(ldap2) < uri.size() &&
	(0 == uri.substr(0, strlen(ldap1)).compare(ldap1) || 0 == uri.substr(0, strlen(ldap2)).compare(ldap2)))
	ldap_uri = uri;
    else
	ldap_uri = std::string(ssl ? ldap1 : ldap2) + uri;
}

Ldap::Server::Server(const std::string & uri, bool ssl) : ldap_object(NULL), ldap_errno(0)
{
    CreateURI(uri, ssl);
}

Ldap::Server::~Server()
{
    if(ldap_object) Disconnect();
}

const std::string & Ldap::Server::URI(void) const
{
    return ldap_uri;
}

const std::string & Ldap::Server::BindDN(void) const
{
    return ldap_bind_dn;
}

bool Ldap::Server::Connect(const std::string & uri, bool ssl)
{
    if(uri.size())
	CreateURI(uri, ssl);

    if(ldap_object) Disconnect();

    const int protocol_version = 3;
    ldap_errno = ldap_initialize(&ldap_object, ldap_uri.c_str());
    if(ldap_object) ldap_set_option(ldap_object, LDAP_OPT_PROTOCOL_VERSION, &protocol_version);

    return LDAP_SUCCESS == ldap_errno;
}

void Ldap::Server::Disconnect(void)
{
    if(ldap_object) Unbind();

    ldap_uri.clear();
}

bool Ldap::Server::Bind(const std::string & bind_dn, const std::string & bind_pw)
{
    ldap_bind_dn = bind_dn;
    ldap_bind_pw = bind_pw;

    return Bind();
}

bool Ldap::Server::Bind(void)
{
    if(!ldap_object) Connect();

    struct berval cred;

    cred.bv_val = const_cast<char *>(ldap_bind_pw.c_str());
    cred.bv_len = ldap_bind_pw.size();

    ldap_errno = ldap_sasl_bind_s(ldap_object, ldap_bind_dn.c_str(), NULL, &cred, NULL, NULL, NULL);

    return LDAP_SUCCESS == ldap_errno;
}

void Ldap::Server::Unbind(void)
{
    if(ldap_object) ldap_errno = ldap_unbind_ext_s(ldap_object, NULL, NULL);

    ldap_bind_dn.clear();
    ldap_bind_pw.clear();

    ldap_object = NULL;
}

bool Ldap::Server::Add(const Entry & entry)
{
    if(ldap_object)
    {
	LDAPMod** mod = reinterpret_cast<LDAPMod**>(const_cast<Mod**>(&entry[0]));
	ldap_errno = ldap_add_ext_s(ldap_object, entry.DN().c_str(), mod, NULL, NULL);
	return LDAP_SUCCESS == ldap_errno;
    }

    return false;
}

bool Ldap::Server::Modify(const Entry & entry)
{
    if(ldap_object)
    {
	LDAPMod** mod = reinterpret_cast<LDAPMod**>(const_cast<Mod**>(&entry[0]));
	ldap_errno = ldap_modify_ext_s(ldap_object, entry.DN().c_str(), mod, NULL, NULL);
	return LDAP_SUCCESS == ldap_errno;
    }

    return false;
}

bool Ldap::Server::Compare(const std::string & attr, const std::string & val) const
{
    return ldap_object &&
	LDAP_COMPARE_TRUE == ldap_compare_ext_s(ldap_object, attr.c_str(), val.c_str(), NULL, NULL, NULL);
}

const char* Ldap::Server::Message(void) const
{
    return ldap_object ? ldap_err2string(ldap_errno) : NULL;
}

bool Ldap::Server::ModDN(const std::string & dn, const std::string & newdn)
{
    return ldap_object &&
	LDAP_SUCCESS == (ldap_errno = ldap_rename_s(ldap_object, dn.c_str(), newdn.c_str(), NULL, 1, NULL, NULL));
}

bool Ldap::Server::Delete(const std::string & dn)
{
    return ldap_object &&
	LDAP_SUCCESS == (ldap_errno = ldap_delete_ext_s(ldap_object, dn.c_str(), NULL, NULL));
}

Ldap::Entries Ldap::Server::Search(const std::string & base, scope_t scope, const std::string & filter, const Attrs* attrs)
{
    Entries result;

    // prepare ldap attrs
    char** ldap_attrs = attrs && attrs->size() ? new char* [ attrs->size() + 1 ] : NULL;

    if(ldap_attrs)
    {
	char** ptr = ldap_attrs;

	for(Attrs::const_iterator
	    it = attrs->begin(); it != attrs->end(); ++it)
	    *ptr++ = const_cast<char*>((*it).c_str());

	*ptr = NULL;
    }

    LDAPMessage *res = NULL;

    // search
    ldap_errno = ldap_search_ext_s(ldap_object, (base.empty() ? NULL : base.c_str()), scope,
			(filter.empty() ? NULL : filter.c_str()), ldap_attrs, 0, NULL, NULL, NULL, 0, & res);

    // insert entries
    if(LDAP_SUCCESS == ldap_errno &&
	0 != ldap_count_entries(ldap_object, res))
    {
	for(LDAPMessage* ldap_entry = ldap_first_entry(ldap_object, res);
		    ldap_entry; ldap_entry = ldap_next_entry(ldap_object, ldap_entry))
	{
	    char* dn = ldap_get_dn(ldap_object, ldap_entry);

    	    result.push_back(Entry(dn));
    	    Entry & current_entry = result.back();

	    BerElement* ber = NULL;

    	    for(char* ldap_attr = ldap_first_attribute(ldap_object, ldap_entry, &ber);
			ldap_attr; ldap_attr = ldap_next_attribute(ldap_object, ldap_entry, ber))
    	    {
#ifdef LDAP_DEPRECATED
		if(char** vals = ldap_get_values(ldap_object, ldap_entry, ldap_attr))
		{
		    size_t count = ldap_count_values(vals);
		    if(count)
		    {
			Entry::iterator it = current_entry.PushBack(new Mod(0, ldap_attr));
			for(size_t ii = 0; ii < count; ++ii)
			    (*it)->Append(vals[ii]);
		    }
    		    ldap_value_free(vals);
		}
		else
#endif
		if(berval** vals = ldap_get_values_len(ldap_object, ldap_entry, ldap_attr))
		{
		    size_t count = ldap_count_values_len(vals);
		    if(count)
		    {
			Entry::iterator it = current_entry.PushBack(new Mod(0, ldap_attr));
			for(size_t ii = 0; ii < count; ++ii)
			    (*it)->Append(vals[ii]->bv_val, vals[ii]->bv_len);
		    }
    		    ldap_value_free_len(vals);
		}
    		ldap_memfree(ldap_attr);
    	    }

    	    if(ber) ber_free(ber, 0);
	    if(dn) ldap_memfree(dn);
	}
    }

    if(res) ldap_msgfree(res);
    if(ldap_attrs) delete [] ldap_attrs;

    return result;
}

bool Ldap::Server::Ping(void) const
{
    if(ldap_object)
    {
	LDAPMessage* res = NULL;
	int errno = ldap_search_ext_s(ldap_object, NULL, BASE, NULL, NULL, 0, NULL, NULL, NULL, 0, & res);
	if(res) ldap_msgfree(res);

	return LDAP_SERVER_DOWN != errno;
    }

    return false;
}

int Ldap::Server::Error(void) const
{
    return ldap_errno;
}

std::ostream & Ldap::operator<< (std::ostream & os, const Entries & entries)
{
    std::copy(entries.begin(), entries.end(), std::ostream_iterator<Entry>(os, "\n"));
    return os;
}
