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

#include "mainwindow.h"
#include "ui_serverdialog.h"

#include <QApplication>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QContextMenuEvent>
#include <QHeaderView>
#include <QDebug>

LdapServerItem::LdapServerItem(const QString & uri)
{
    setText(0, uri);
}

bool LdapServerItem::connect(const QString & uri)
{
    return Connect(uri.toStdString());
}

bool LdapServerItem::bind(void)
{
    return Bind();
}

bool LdapServerItem::bind(const QString & login, const QString & pass)
{
    return Bind(login.toStdString(), pass.toStdString());
}

QString LdapServerItem::message(void) const
{
    return Message();
}

QString LdapServerItem::baseDN(void)
{
    return BaseDN().c_str();
}

Ldap::ListEntries LdapServerItem::search(const QString & base, Ldap::Scope scope, const QString & filter)
{
    return Search(base.toStdString(), scope);
}

LdapEntryItem::LdapEntryItem(const Ldap::Entry & entry) : Ldap::Entry(entry)
{
    QString str(entry.DN().c_str());
    setText(0, str);
    setToolTip(0, str);
}

QString LdapEntryItem::dn(void)
{
    return DN().c_str();
}

LdapServerItem* LdapEntryItem::ldap(void)
{
    QTreeWidgetItem* top = this;
    while(top->parent()) top = top->parent();

    return static_cast<LdapServerItem*>(top);
}

QStringList LdapEntryItem::attributes(void) const
{
    QStringList res;
    for(auto & ptr : Ldap::Entry::values)
        if(ptr) res << QString(ptr->GetType());
    return res;
}

QString LdapEntryItem::value(const QString & attr) const
{
    return QString::fromStdString(Ldap::Entry::GetStringValue(attr.toStdString()));
}

QStringList LdapEntryItem::values(const QString & attr) const
{
    QStringList res;
    for(auto & str : Ldap::Entry::GetStringList(attr.toStdString()))
	res << QString::fromStdString(str);
    return res;
}

TreeList::TreeList(QWidget* parent) : QTreeWidget(parent)
{
    setHeaderLabel("ldap");
    //setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);

    actionAddServer = new QAction(QIcon(":/icons/server_add.png"), tr("Add"), this);
    actionDeleteServer = new QAction(QIcon(":/icons/server_del.png"), tr("Delete"), this);
    actionEditServer = new QAction(tr("Edit"), this);

    actionDeleteServer->setDisabled(true);
    actionEditServer->setDisabled(true);

    connect(actionAddServer, SIGNAL(triggered()), this, SLOT(addLdapServerItem()));
}

void TreeList::contextMenuEvent(QContextMenuEvent* event)
{
    QMenu menu(this);
    menu.addAction(actionAddServer);
    menu.addAction(actionEditServer);
    menu.addSeparator();
    menu.addAction(actionDeleteServer);
    menu.exec(event->globalPos());
}

void TreeList::addLdapServerItem(void)
{
    auto dialog = new QDialog;
    Ui::ConnectionInfoDialog ui;
    ui.setupUi(dialog);

    if(QDialog::Accepted == dialog->exec())
    {
	const QString & uri = ui.lineEditURI->text();
	const QString & login = ui.lineEditLogin->text();
	const QString & pass = ui.lineEditPass->text();

	LdapServerItem* ldap = new LdapServerItem(uri);
	if(ldap->connect(uri))
	{
    	    if(ldap->bind(login, pass))
        	addTopLevelItem(ldap);
    	    else
	    {
		emit updateStatusBar(QString("ldap bind: ").append(ldap->message()));
	    }
	}
	else
	{
    	    emit updateStatusBar(QString("ldap connect: ").append(ldap->message()));
	}
    }
}

TableWidget::TableWidget(QWidget* parent) : QTableWidget(parent)
{
    setColumnCount(2);
    setRowCount(0);
    setHorizontalHeaderLabels({ "attribute", "value" });

    //setFocusPolicy(Qt::NoFocus);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setSelectionMode(QAbstractItemView::SingleSelection);

    //setShowGrid(false);
    //setSizePolicy(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
    horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    menuBar = new QMenuBar(this);
    menuBar->setGeometry(QRect(0, 0, 684, 19));
    setMenuBar(menuBar);

    mainToolBar = new QToolBar(this);
    addToolBar(Qt::TopToolBarArea, mainToolBar);

    statusBar = new QStatusBar(this);
    setStatusBar(statusBar);

    centralWidget = new QWidget(this);
    treeList = new TreeList(centralWidget);
    tableWidget = new TableWidget(centralWidget);

    widgetLayout = new QHBoxLayout(centralWidget);
    widgetLayout->setSpacing(6);
    widgetLayout->setContentsMargins(11, 11, 11, 11);
    widgetLayout->addWidget(treeList);
    widgetLayout->addWidget(tableWidget);

    scrollLayout = new QVBoxLayout(tableWidget);
    scrollLayout->setSpacing(6);
    scrollLayout->setContentsMargins(11, 11, 11, 11);

    setCentralWidget(centralWidget);
    setWindowTitle(QApplication::translate("MainWidow", "QLdapBrowser", 0));

    connect(treeList, SIGNAL(itemClicked(QTreeWidgetItem*, int)), this, SLOT(treeItemClicked(QTreeWidgetItem*, int)));
    connect(treeList, SIGNAL(updateStatusBar(const QString &)), statusBar, SLOT(showMessage(const QString &)));
}

void MainWindow::treeItemClicked(QTreeWidgetItem* treeItem, int column)
{
    LdapEntryItem* entry = dynamic_cast<LdapEntryItem*>(treeItem);
    LdapServerItem* ldap = entry ? entry->ldap() : dynamic_cast<LdapServerItem*>(treeItem);

    if(treeItem->childCount() == 0)
    {
        if(entry)
        {
            statusBar->showMessage("ldap search...");

            for(auto & val : ldap->search(entry->dn(), Ldap::ScopeOne, ""))
                treeItem->addChild(new LdapEntryItem(val));
        }
        else
        if(ldap)
        {
	    // add base dn
            auto entries = ldap->search(ldap->baseDN(), Ldap::ScopeBase, "");
            if(entries.empty()) qFatal("base dn failed");
            treeItem->addChild(new LdapEntryItem(entries.front()));
        }
    }

    if(entry)
    {
        statusBar->showMessage(QString("dn: ").append(entry->dn()));
	tableWidget->setRowCount(entry->attributes().size());
	int row = 0;

	for(auto & str : entry->attributes())
	{
            tableWidget->setItem(row, 0, new QTableWidgetItem(str));
            tableWidget->setItem(row, 1, new QTableWidgetItem(entry->value(str)));
	    row++;
        }
    }
}
