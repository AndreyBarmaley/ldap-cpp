#-------------------------------------------------
#
# Project created by QtCreator 2018-05-05T17:08:43
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QLdapBrowser
TEMPLATE = app

RESOURCES = resources.qrc

SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += \
    serverdialog.ui

HEADERS += ../cldap_entry.h ../cldap.h ../cldap_mod.h ../cldap_server.h ../cldap_types.h
SOURCES += ../cldap_entry.cpp ../cldap_mod.cpp ../cldap_server.cpp

LIBS += -lldap -llber -lcrypto -lssl
