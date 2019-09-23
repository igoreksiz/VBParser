#ifndef COMMON_H
#define COMMON_H

#include <QMainWindow>
#include <QFileDialog>
#include <QThread>
#include <QString>
#include <QDialog>
#include <QApplication>
#include <QDir>
#include <QTreeWidget>
#include <QMessageBox>
#include <QDebug>
#include <QSignalMapper>
#include <QMenu>
#include <QProcess>
#include <QTextEdit>
#include <QScrollBar>
#include <QDateTime>
#include <QMetaEnum>
#include <QTextCodec>
#include <QDropEvent>
#include <QMimeData>
#include <QUuid>
#include <stdint.h>

typedef char CHAR, *PCHAR;
typedef wchar_t WCHAR, *PWCHAR;

typedef int32_t LONG;

typedef uint8_t BYTE, *PBYTE;
typedef uint16_t WORD, USHORT, *PWORD;
typedef uint32_t DWORD, ULONG, *PDWORD;
typedef uint64_t QWORD, ULONGLONG, *PQWORD;
typedef void *PVOID;
typedef BYTE BOOL;

typedef struct tagSAFEARRAYBOUND
{
    ULONG cElements;
    LONG lLbound;
} SAFEARRAYBOUND;

typedef struct tagSAFEARRAY
{
    USHORT cDims;
    USHORT fFeatures;
    ULONG cbElements;
    ULONG cLocks;
    PVOID pvData;
    SAFEARRAYBOUND rgsabound[ 1 ];
} SAFEARRAY;

typedef struct {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} UUID, *PUUID;

#define CONTAINING_RECORD(address, type, field) ((type *)((PCHAR)(address) - (qint64)(&((type *)0)->field)))

#define min(x, y) ((x) <= (y) ? (x) : (y))
#define max(x, y) ((x) >= (y) ? (x) : (y))

// Functions

QString buildHexTable(const unsigned char* pBuffer, unsigned int Size);
QString buildHexTableMask(const unsigned char* pBuffer, QVector<BYTE> mask, BYTE bGoodMask, bool Questions = true);
void ShowInExplorer(QString pathIn);

QString DWORDToString(DWORD n);
QString WORDToString(WORD n);

QString uuidToString(UUID* pUuid);

inline DWORD ROL(DWORD x, int n) {
    return (x << n )| (x >> (32 - n));
}

#endif // COMMON_H
