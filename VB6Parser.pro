#-------------------------------------------------
#
# Project created by QtCreator 2016-11-04T19:56:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = VB6Parser
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    settings.cpp \
    vbfile.cpp \
    filescanner.cpp \
    pe_format.cpp \
    vb5_6.cpp \
    common.cpp

HEADERS  += mainwindow.h \
    settings.h \
    vbfile.h \
    filescanner.h \
    common.h \
    pe_format.h \
    vb5_6.h \
    comp_id.h

FORMS    += mainwindow.ui \
    settings.ui

RESOURCES += \
    res.qrc
