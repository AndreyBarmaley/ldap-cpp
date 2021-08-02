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

#include <iterator>
#include <algorithm>

#include "cldap_entry.h"

Ldap::Entry::Entry(const std::string & str) : dn(str)
{
    values.reserve(32);
}

void Ldap::Entry::SetDN(const std::string & str)
{
    dn = str;
}

const std::string & Ldap::Entry::DN(void) const
{
    return dn;
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::string & value)
{
    auto mod = FindOrPush(attr, op, false);
    if(mod && value.size())
	mod->Append(value);
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector<std::string> & vals)
{
    auto mod = FindOrPush(attr, op, false);
    if(mod)
    {
	for(auto & val : vals)
	    mod->Append(val);
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::list<std::string> & vals)
{
    auto mod = FindOrPush(attr, op, false);
    if(mod)
    {
	for(auto & val : vals)
	    mod->Append(val);
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector<char> & value)
{
    if(attr.size() && value.size())
    {
	auto mod = FindOrPush(attr, op, true);
	mod->Append(value);
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector< std::vector<char> > & vals)
{
    auto mod = FindOrPush(attr, op, true);
    if(mod)
    {
	for(auto & val : vals)
	    mod->Append(val);
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::list< std::vector<char> > & vals)
{
    auto mod = FindOrPush(attr, op, true);
    if(mod)
    {
	for(auto & val : vals)
	    mod->Append(val);
    }
}

std::list<std::string> Ldap::Entry::GetAttributes(void) const
{
    std::list<std::string> res;

    for(auto & ptr: values)
	if(ptr) res.emplace_back(ptr->GetType());

    return res;
}

std::string Ldap::Entry::GetStringValue(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetStringValue();
    }

    return std::string();
}

std::vector<std::string>
Ldap::Entry::GetStringValues(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetStringValues();
    }

    return std::vector<std::string>();
}

std::list<std::string>
Ldap::Entry::GetStringList(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetStringList();
    }

    return std::list<std::string>();
}

std::vector<char> Ldap::Entry::GetBinaryValue(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetBinaryValue();
    }

    return std::vector<char>();
}

std::vector< std::vector<char> >
Ldap::Entry::GetBinaryValues(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetBinaryValues();
    }

    return std::vector< std::vector<char> >();
}

std::list< std::vector<char> >
Ldap::Entry::GetBinaryList(const std::string & attr) const
{
    if(attr.size())
    {
	auto it = std::find_if(values.begin(), values.end(), [&](auto & ptr){ return ptr && ptr->IsType(attr); });

	if(it != values.end())
	    return (*it)->GetBinaryList();
    }

    return std::list< std::vector<char> >();
}

Ldap::ModBase* Ldap::Entry::FindOrPush(const std::string & attr, int op, bool binary)
{
    if(attr.empty())
	return NULL;

    auto it = std::find_if(values.begin(), values.end(),
	    [&](auto & ptr){ return ptr && ptr->IsBinary() == binary && ptr->IsType(attr) && ptr->IsOperation(op); });
    if(it != values.end()) return (*it).get();

    ModBase* mod = binary ? static_cast<ModBase*>(new ModBin(op, attr)) : static_cast<ModBase*>(new ModStr(op, attr));
    values.emplace_back(mod);

    return mod;
}

std::vector<LDAPMod*> Ldap::Entry::toLDAPMods(void) const
{
    std::vector<LDAPMod*> v;
    v.reserve(values.size() + 1);

    for(auto & ptr : values)
	if(ptr) v.push_back(const_cast<LDAPMod*>(ptr->toLDAPMod()));

    return v;
}

std::ostream & Ldap::operator<< (std::ostream & os, const Entry & entry)
{
    os << Base64::StringWrap("dn", entry.dn) << std::endl;

    for(auto & ptr : entry.values)
    {
	if(ptr->IsBinary())
	{
	    const ModBin* mod = static_cast<const ModBin*>(ptr.get());
	    if(mod) os << *mod;
	}
	else
	{
	    const ModStr* mod = static_cast<const ModStr*>(ptr.get());
	    if(mod) os << *mod;
	}
    }

    return os;
}
