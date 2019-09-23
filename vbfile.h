#ifndef VBFILE_H
#define VBFILE_H

#include "common.h"
#include "pe_format.h"
#include "vb5_6.h"
#include "comp_id.h"

class Exception : public QObject {
 Q_OBJECT
 public:
    typedef enum {
        EXCEPTION_UNKNOWN = 0,
        EXCEPTION_FILE_NOT_OPEN,
        EXCEPTION_FILE_TOO_BIG,
        EXCEPTION_FILE_NOT_PE,
        EXCEPTION_FILE_NOT_PE32,
        EXCEPTION_FILE_NOT_VISUAL_BASIC_5_6,
    } VBFileException;
    Q_ENUM(VBFileException)
 };

typedef enum {
    LEAK_GENERIC = 0,
    LEAK_RESOURCE_MAJOR,
    LEAK_RESDESCR_PUBLICBYTES,
    LEAK_RESDESCR_STATICBYTES,
    LEAK_METHOD_POINTERS,
    LEAK_METHOD_NAME_POINTERS,
    LEAK_METHOD_COM_OBBJECT,
} VBLeakType;

class VBFile;

class MemoryDisclosure {
    friend VBFile;
public:
    static const BYTE MASK_LEAK = 'x';
    static const BYTE MASK_VALID = '*';
    static const BYTE MASK_UNSURE = '?';
private:
    const qint64 MAX_VISUAL_BASIC_STRING_LENGTH = 1024;
    QVector<BYTE> leakMap;
    // unpacked state
    PBYTE pData;
    PBYTE pDataEnd;
    qint64 nCount;
    // packed state
    QByteArray Data;
    QString LeakName;
    //
    inline bool isInRange(PVOID p, qint64 len) {
        return pData <= (PBYTE)p && (PBYTE)p + len < pDataEnd;
    }
private:
    void maskSet(qint64 offset, qint64 len, BYTE mask) {
        Q_ASSERT(pDataEnd);
        while (!isInRange(pData + offset, len))
            len--;
        if (offset + len > leakMap.size())
            leakMap.resize(offset + len);
        for (qint64 i = offset; i < offset + len; i++)
            leakMap[i] = mask;
    }
    // Visual Basic 5/6 string with 4 byte alignment
    void visualBasicMaskString(qint64 offset, bool bHaveLeak = true) {
        Q_ASSERT(pDataEnd);
        qint64 p = offset;
        do {
            if (!isInRange(pData + p, sizeof(BYTE)))
                return;
            if (p + 1 > (qint64)leakMap.size())
                leakMap.resize(p + 1);
            leakMap[p] = MASK_VALID;
        } while (pData[p++] && p - offset < MAX_VISUAL_BASIC_STRING_LENGTH);
        if (bHaveLeak) {
            DWORD p_aligned = ALIGN_UP(p, 4); // !!! check: 4 vs 8 !!!
            maskSet(p, p_aligned - p, MASK_LEAK); // leak at align
        }
    }
    bool packLeak(bool bOptimize) {
        if (bOptimize) {
            while (leakMap.size() && leakMap[0] == MASK_UNSURE) {
                pData++;
                leakMap.removeFirst();
            }
            while (leakMap.size() && leakMap[0] == MASK_VALID) {
                pData++;
                leakMap.removeFirst();
            }
            while (leakMap.size() && leakMap[leakMap.size() - 1] == MASK_UNSURE)
                leakMap.removeLast();
            while (leakMap.size() && leakMap[leakMap.size() - 1] == MASK_VALID)
                leakMap.removeLast();
        }
        bool isAllZero = true;
        for (int i = 0; i<leakMap.size(); i++) {
            if (leakMap[i] != MASK_VALID) {
                leakMap[i] = MASK_LEAK;
                isAllZero &= pData[i] == 0x00;
            }
        }
        if (isAllZero)
            return false;
        //
        Data.resize(0);
        Data.append((const char*)pData, leakMap.size());
        pData = NULL;
        pDataEnd = NULL;
        nCount = 0;
        return true;
    }
    void setName(QString LeakName) {
        this->LeakName = LeakName;
    }
public:
    MemoryDisclosure(PBYTE pData, qint64 nCount, PBYTE pDataEnd, QString LeakName) {
        this->pData = pData;
        this->nCount = nCount;
        this->pDataEnd = pDataEnd;
        leakMap.resize(nCount);
        for (int i = 0 ; i < nCount; i++)
            leakMap[i] = MASK_UNSURE;
        this->LeakName = LeakName;
    }
    QString getName() {
        Q_ASSERT(!pDataEnd);
        return LeakName;
    }
    QByteArray getData() {
        Q_ASSERT(!pDataEnd);
        return Data;
    }
    QVector<BYTE>& getLeakMap() {
        Q_ASSERT(!pDataEnd);
        return leakMap;
    }
    QString toHexTable() {
        Q_ASSERT(!pDataEnd);
        return buildHexTableMask((const unsigned char*)Data.data(), leakMap, MASK_LEAK, false);
    }
    QString toMaskedHexTable() {
        Q_ASSERT(!pDataEnd);
        return buildHexTableMask((const unsigned char*)Data.data(), leakMap, MASK_LEAK);
    }
    ~MemoryDisclosure() {

    }
};

class VBFile
{
public:
    static const qint64 VB_DETECT_BY_RAW_SEARCH = 1 << 0;
    //
    static const qint64 VB_LEAK_RES_MAJOR = 1 << 1;
    static const qint64 VB_LEAK_RESDESCTBL = 1 << 2;
    static const qint64 VB_LEAK_METHOD_NAMES = 1 << 3;
    static const qint64 VB_LEAK_METHOD_POINTERS = 1 << 4;
    static const qint64 VB_LEAK_COM_OBJECT = 1 << 5;
    static const qint64 VB_LEAK_PROJET_PATH = 1 << 6;
    //
    static const qint64 VB_SUMMARY_PROJECTPATH = 1 << 7;
    static const qint64 VB_SUMMARY_OLB_PATH = 1 << 8;
    static const qint64 VB_SUMMARY_METHOD_NAMES = 1 << 9;
    static const qint64 VB_SUMMARY_OBJECT_NAMES = 1 << 10;
    static const qint64 VB_SUMMARY_COMPILER_LEFTOVERS = 1 << 11;
    static const qint64 VB_SUMMARY_RICH = 1 << 12;
    static const qint64 VB_SUMMARY_IMPORT = 1 << 13;
    static const qint64 VB_SUMMARY_PE_IMPORT = 1 << 14;
    //
    static const qint64 VB_OPTIMIZE_LEAKS = 1 << 15;
private:
    static const qint64 VB_MAX_FILE_SIZE = 10 * 1024 * 1024;
    static const DWORD MAX_RESOURCES_TO_PARSE = 100;
    //
    static const DWORD RICH_BLOCK_OFFSET = 0x80;
    static const DWORD RICH_SIGNATURE = 0x68636952; // Rich
    static const DWORD DanS_SIGNATURE = 0x536e6144; // DanS
    static const DWORD DEFAULT_MICROSOFT_DOSHEADER_HASH = 0x884f3421;
private:
    QVector<MemoryDisclosure*> leaks;
    QString summary;
    //
    PBYTE pFileData;
    PBYTE pFileDataEnd;
    qint64 nFileSize;
    QByteArray fileBlob;
    bool bOptimizeLeaks;
    int iVBVersion;
    bool bIsUnparsable;
    //
    qint64 options;
    QString charset;
    //
    QSet<RESDESCTBL*> resdscrtbl_checked;
    QSet<PIMAGE_RESOURCE_DIRECTORY> visited_resdirs;
    QSet<DWORD> resource_dir_timestamp;
    //
    PIMAGE_NT_HEADERS32 pNtHeaders;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_DATA_DIRECTORY pResourceDir;
    PIMAGE_DATA_DIRECTORY pImportDir;
    DWORD EntryPoint;
    DWORD ImageBase;
    //
    PEXEPROJECTINFO pVBHeader;
    pVB_ProjInfo pProjData;
    //
    inline void addSummaryLine(QString s) {
        summary += s.toHtmlEscaped() + "<br>";
    }
    inline void addSummaryLineWarning(QString s) {
        //qDebug() << s.toHtmlEscaped();
        summary += "<font color=red>" + s.toHtmlEscaped() + "</font><br>";
    }
    inline PVOID rvaToPointer(DWORD Address) {
        return __ImageRvaToVa32(pNtHeaders, pFileData, Address, NULL);
    }
    inline PVOID vaToPointer(DWORD Address) {
        return rvaToPointer(Address - ImageBase);
    }
    inline bool isValidFilePointer(PVOID p, qint64 size = 0) {
        return (qint64)p >= (qint64)pFileData && (qint64)p - (qint64)pFileData < nFileSize
            && (qint64)p + size >= (qint64)pFileData && (qint64)p - (qint64)pFileData + size < nFileSize;
    }
    QSet<PVOID> findPattern(PBYTE pPattern, qint64 nPatternLen) {
        QSet<PVOID> result;
        for (PBYTE p = pFileData; p < pFileData + nFileSize - nPatternLen; p++)
            if (memcmp(p, pPattern, nPatternLen) == 0)
                result.insert(p);
        return result;
    }
    QString safeReadString(PCHAR p, qint64 maxSize = 256) {
        QString result;
        QTextCodec* codec = QTextCodec::codecForName(charset.toLatin1());
        while (isValidFilePointer(p, sizeof(CHAR)) && *p && result.length() < maxSize) {
            result += codec->toUnicode(p, 1);
            p++;
        }
        return result;
    }
    QString safeReadWideString(PWCHAR p, qint64 maxSize = 256) {
        QString result;
        while (isValidFilePointer(p, sizeof(WCHAR)) && *p && result.length() < maxSize) {
            result += QString::fromWCharArray(p, 1);
            p++;
        }
        return result;
    }
    QString safeReadStringVA(DWORD address, qint64 maxSize = 256) {
        PCHAR p = (PCHAR)vaToPointer(address);
        if (!isValidFilePointer(p, sizeof(CHAR)))
            return QString();
        return safeReadString(p, maxSize);
    }
    inline void addLeak(MemoryDisclosure* leak) {
        if (leak->packLeak(bOptimizeLeaks))
            leaks.append(leak);
        else
            delete leak;
    }

    //
    void ParseLeak_RESDESCTBL(RESDESCTBL* pResDscrTbl, QString strType);
    void ParseLeak_MethodNames(PDWORD pLeakBegin, PDWORD pLeakEnd);
    void ParseLeak_ProjectPath(WCHAR* wsProjectPath, qint64 sizeOfProjectPath);
    void ParseLeak_lpMethods(DWORD lpObjectInfo, PDWORD pdwMethods, WORD wMethodCount);
    void ParseLeak_Objects(pVB_PublicObjectDescr pObjectArray, DWORD dwObjectCount);
    void ParseLeak_COMObject(pVB_ComRegData pComRegData);
    //
    void parseResourceDirectory(PIMAGE_RESOURCE_DIRECTORY pResourceData, PBYTE pResourceBase, DWORD dwResourceDataSize);
    //
    void readVB56Structures();
    void readRichSignature();
    void readResources();
    void readImport();
    //
    void detectEXEPROJDATA();
    void detectProjData();
public:
    VBFile(QString filePath, qint64 options = 0, QString charset = "Windows-1251");
    QVector<MemoryDisclosure*> & getLeaks();
    QString getSummary();
    bool isUnparsable();
    ~VBFile();
};

#endif // VBFILE_H
