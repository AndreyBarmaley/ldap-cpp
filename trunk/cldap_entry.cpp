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

#include "cldap_mod.h"
#include "cldap_server.h"
#include "cldap_entry.h"

Ldap::Entry::Entry(const std::string & dn) : entry_dn(dn)
{
}

Ldap::Entry::Entry(const Entry & entry) : entry_dn(entry.entry_dn), entry_ldapmods(entry.entry_ldapmods)
{
}

Ldap::Entry::~Entry()
{
    if(entry_ldapmods.size())
    {
	std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
	std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();
	
	for(; it1 != it2; ++it1) delete *it1;
    }
}

Ldap::Entry & Ldap::Entry::operator= (const Entry & entry)
{
    entry_dn = entry.entry_dn;
    entry_ldapmods = entry.entry_ldapmods;

    return *this;
}

void Ldap::Entry::DN(const std::string & dn)
{
    entry_dn = dn;
}

const std::string & Ldap::Entry::DN(void) const
{
    return entry_dn;
}

Ldap::Mod * Ldap::Entry::Find(const std::string & attr, actions_t action, bool binary)
{
    std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
    std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();

    for(; it1 != it2; ++it1)
    {
	if(*it1)
	{
	    const Mod & mod = **it1;

	    if(mod.mod_op == (binary ? action | LDAP_MOD_BVALUES : action) && 0 == strcmp(mod.mod_type, attr.c_str())) return *it1;
	}
    }

    return NULL;
}

void Ldap::Entry::Replace(const std::string & attr, const std::string & value)
{
    if(Mod *mod = Find(attr, REPLACE))
	mod->Append(value);
    else
	entry_ldapmods.push_back(new Mod(attr, value, REPLACE));
}

void Ldap::Entry::Replace(const std::string & attr, const std::vector<char> & value)
{
    if(Mod *mod = Find(attr, REPLACE, true))
	mod->Append(value);
    else
	entry_ldapmods.push_back(new Mod(attr, value, ADD));
}

void Ldap::Entry::Replace(const std::string & attr, const std::list<std::string> & values)
{
    std::list<std::string>::const_iterator it1 = values.begin();
    std::list<std::string>::const_iterator it2 = values.end();
    
    for(; it1 != it2; ++it1) Replace(attr, *it1);
}

void Ldap::Entry::Delete(const std::string & attr, const std::string & value)
{
    entry_ldapmods.push_back(new Mod(attr, value, DELETE));
}

void Ldap::Entry::Delete(const std::string & attr, const std::vector<char> & values)
{
    entry_ldapmods.push_back(new Mod(attr, values, DELETE));
}

void Ldap::Entry::Delete(const std::string & attr, const std::list<std::string> & values)
{
    entry_ldapmods.push_back(new Mod(attr, values, DELETE));
}

void Ldap::Entry::Add(const std::string & attr, const std::vector<char> & value)
{
    if(Mod *mod = Find(attr, ADD, true))
	mod->Append(value);
    else
	entry_ldapmods.push_back(new Mod(attr, value, ADD));
}

void Ldap::Entry::Add(const std::string & attr, const std::string & value)
{
    if(Mod *mod = Find(attr, ADD))
	mod->Append(value);
    else
	entry_ldapmods.push_back(new Mod(attr, value, ADD));
}

void Ldap::Entry::Add(const std::string & attr, const std::list<std::string> & values)
{
    std::list<std::string>::const_iterator it1 = values.begin();
    std::list<std::string>::const_iterator it2 = values.end();
    
    for(; it1 != it2; ++it1) Add(attr, *it1);
}

void Ldap::Entry::Modify(const LDAPMod **ldapmods)
{
    entry_ldapmods.push_back(new Mod());
}

void Ldap::Entry::Dump(std::ostream & stream) const
{
    stream << "dn: " << entry_dn << std::endl;

    if(entry_ldapmods.size())
    {
	std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
	std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();

        for(; it1 != it2; ++it1) if(*it1) (**it1).Dump(stream);
    }
}

LDAPMod** Ldap::Entry::c_LDAPMod(void)
{
    if(entry_ldapmods.empty() || entry_ldapmods.back()) entry_ldapmods.push_back(NULL);

    return reinterpret_cast<LDAPMod **>(&entry_ldapmods[0]);
}

const Ldap::Mod* Ldap::Entry::Exists(const std::string & attr) const
{
    if(entry_ldapmods.size())
    {
	std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
	std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();

	for(; it1 != it2; ++it1)
	    if(*it1 && attr == (*it1)->Attr()) return *it1;
    }

    return NULL;
}

const Ldap::Mod* Ldap::Entry::Exists(const std::string & attr, const std::string & val) const
{
    if(entry_ldapmods.size())
    {
	std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
	std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();

	for(; it1 != it2; ++it1)
	    if(*it1 && attr == (*it1)->Attr() && (*it1)->Exists(val)) return *it1;
    }

    return NULL;
}

const Ldap::Mod* Ldap::Entry::Exists(const std::string & attr, const std::vector<char> & val) const
{
    if(entry_ldapmods.size())
    {
	std::vector<Mod *>::const_iterator it1 = entry_ldapmods.begin();
	std::vector<Mod *>::const_iterator it2 = entry_ldapmods.end();

	for(; it1 != it2; ++it1)
	    if(*it1 && attr == (*it1)->Attr() && (*it1)->Exists(val)) return *it1;
    }

    return NULL;
}

void Ldap::Entry::GetValue(const std::string & attr, std::string & result) const
{
    if(const Mod* mod = Exists(attr)) mod->GetValue(result);
}

void Ldap::Entry::GetValue(const std::string & attr, std::vector<char> & result) const
{
    if(const Mod* mod = Exists(attr)) mod->GetValue(result);
}

void Ldap::Entry::GetValues(const std::string & attr, std::list<std::string> & result) const
{
    if(const Mod* mod = Exists(attr)) mod->GetValues(result);
}

void Ldap::Entry::GetValues(const std::string & attr, std::list< std::vector<char> > & result) const
{
    if(const Mod* mod = Exists(attr)) mod->GetValues(result);
}
