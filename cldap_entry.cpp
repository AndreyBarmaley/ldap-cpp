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

Ldap::Entry::Entry(const std::string & str) : dn(str)
{
    reserve(32);
    push_back(NULL);
}

Ldap::Entry::~Entry(void)
{
    for(iterator it = begin(); it != end(); ++it) delete *it;
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
    if(attr.size() && value.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	(*it)->Append(value.c_str());
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector<std::string> & values)
{
    if(attr.size() && values.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	for(std::vector<std::string>::const_iterator
	    it2 = values.begin(); it2 != values.end(); ++it2)
	    (*it)->Append((*it2).c_str());
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::list<std::string> & values)
{
    if(attr.size() && values.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	for(std::list<std::string>::const_iterator
	    it2 = values.begin(); it2 != values.end(); ++it2)
	    (*it)->Append((*it2).c_str());
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector<char> & value)
{
    if(attr.size() && value.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	(*it)->Append(&value[0], value.size());
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::vector< std::vector<char> > & values)
{
    if(attr.size() && values.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	for(std::vector< std::vector<char> >::const_iterator
	    it2 = values.begin(); it2 != values.end(); ++it2)
	    (*it)->Append(&(*it2)[0], (*it2).size());
    }
}

void Ldap::Entry::Append(int op, const std::string & attr, const std::list< std::vector<char> > & values)
{
    if(attr.size() && values.size())
    {
	iterator it = begin();

	for(; it != end(); ++it)
	    if(*it && (*it)->IsType(attr.c_str()) && (*it)->IsOperation(op)) break;

	if(it == end())
	    it = PushBack(new Mod(op, attr.c_str()));

	for(std::list< std::vector<char> >::const_iterator
	    it2 = values.begin(); it2 != values.end(); ++it2)
	    (*it)->Append(&(*it2)[0], (*it2).size());
    }
}

std::string Ldap::Entry::GetStringValue(const std::string & attr) const
{
    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		if(bvals && bvals[0])
		    return std::string(bvals[0]->bv_val, bvals[0]->bv_len);
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		if(vals && vals[0])
		    return std::string(vals[0]);
	    }
	}
    }

    return std::string();
}

std::vector<std::string>
Ldap::Entry::GetStringValues(const std::string & attr) const
{
    std::vector<std::string> res;

    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		while(bvals && *bvals)
		{
		    res.push_back(std::string((*bvals)->bv_val, (*bvals)->bv_len));
		    ++bvals;
		}
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		while(vals && *vals)
		{
		    res.push_back(std::string(*vals));
		    ++vals;
		}
	    }
	}
    }

    return res;
}

std::list<std::string>
Ldap::Entry::GetStringList(const std::string & attr) const
{
    std::list<std::string> res;

    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		while(bvals && *bvals)
		{
		    res.push_back(std::string((*bvals)->bv_val, (*bvals)->bv_len));
		    ++bvals;
		}
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		while(vals && *vals)
		{
		    res.push_back(std::string(*vals));
		    ++vals;
		}
	    }
	}
    }

    return res;
}

std::vector<char> Ldap::Entry::GetBinaryValue(const std::string & attr) const
{
    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		if(bvals && bvals[0])
		    return std::vector<char>(bvals[0]->bv_val, bvals[0]->bv_val + bvals[0]->bv_len);
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		if(vals && vals[0])
		    return std::vector<char>(vals[0], vals[0] + strlen(vals[0]));
	    }
	}
    }

    return std::vector<char>();
}

std::vector< std::vector<char> >
Ldap::Entry::GetBinaryValues(const std::string & attr) const
{
    std::vector< std::vector<char> > res;

    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		while(bvals && *bvals)
		{
		    res.push_back(std::vector<char>((*bvals)->bv_val, (*bvals)->bv_val + (*bvals)->bv_len));
		    ++bvals;
		}
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		while(vals && *vals)
		{
		    res.push_back(std::vector<char>(*vals, *vals + strlen(*vals)));
		    ++vals;
		}
	    }
	}
    }

    return res;
}

std::list< std::vector<char> >
Ldap::Entry::GetBinaryList(const std::string & attr) const
{
    std::list< std::vector<char> > res;

    if(attr.size())
    {
	const_iterator it = find_if(begin(), end(), std::bind2nd(std::mem_fun(&Mod::IsType), attr.c_str()));

	if(it != end() && *it)
	{
	    if(const berval* const* bvals = (*it)->GetBinValues())
	    {
		while(bvals && *bvals)
		{
		    res.push_back(std::vector<char>((*bvals)->bv_val, (*bvals)->bv_val + (*bvals)->bv_len));
		    ++bvals;
		}
	    }
	    else
	    if(const char* const* vals = (*it)->GetStrValues())
	    {
		while(vals && *vals)
		{
		    res.push_back(std::vector<char>(*vals, *vals + strlen(*vals)));
		    ++vals;
		}
	    }
	}
    }

    return res;
}

Ldap::Entry::iterator Ldap::Entry::PushBack(Mod* mod)
{
    push_back(NULL);
    iterator it = std::find(begin(), end(), static_cast<Mod*>(0));
    *it = mod;
    return it;
}

std::ostream & Ldap::operator<< (std::ostream & os, const Entry & entry)
{
    os << "dn: " << entry.dn << std::endl;

    for(Entry::const_iterator
	it = entry.begin(); it != entry.end(); ++it)
	if(*it) os << **it;

    return os;
}

