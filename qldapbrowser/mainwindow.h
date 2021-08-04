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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTableWidget>
#include <QStringList>

QT_BEGIN_NAMESPACE
class QWidget;
class QHBoxLayout;
class QVBoxLayout;
class QMenuBar;
class QToolBar;
class QStatusBar;
class QAction;
QT_END_NAMESPACE

#include "../cldap.h"

class LdapServerItem : public QTreeWidgetItem, protected Ldap::Server
{
public:
    LdapServerItem(const QString &);

    bool                connect(const QString &);
    bool                bind(void);
    bool                bind(const QString &, const QString &);
    QString             baseDN(void);
    Ldap::ListEntries   search(const QString &, Ldap::Scope, const QString & filter);

    QString             message(void) const;
};

class LdapEntryItem : public QTreeWidgetItem, protected Ldap::Entry
{
public:
    LdapEntryItem(const Ldap::Entry &);

    QString             dn(void);
    LdapServerItem*     ldap(void);

    QStringList		attributes(void) const;
    QString		value(const QString &) const;
    QStringList		values(const QString &) const;
};

class TreeList : public QTreeWidget
{
    Q_OBJECT

public:
    TreeList(QWidget*);

signals:
    void		updateStatusBar(const QString &);

protected slots:
    void        	addLdapServerItem(void);

protected:
    void        	contextMenuEvent(QContextMenuEvent*);

    QAction*    	actionAddServer;
    QAction*    	actionDeleteServer;
    QAction*    	actionEditServer;
};

class TableWidget : public QTableWidget
{
    Q_OBJECT

public:
    TableWidget(QWidget*);

protected:
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);

protected slots:
    void        	treeItemClicked(QTreeWidgetItem*, int);

private:
    QWidget*        	centralWidget;
    QHBoxLayout*    	widgetLayout;
    QVBoxLayout*    	scrollLayout;
    TreeList*       	treeList;
    TableWidget*     	tableWidget;
    QMenuBar*       	menuBar;
    QToolBar*       	mainToolBar;
    QStatusBar*     	statusBar;
};

#endif // MAINWINDOW_H
