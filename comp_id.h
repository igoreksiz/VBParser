#ifndef COMP_ID_H
#define COMP_ID_H

#include "common.h"

class CompId {
private:
    QMap <DWORD, QString> compid_description;
    CompId() {
        QFile compid_file("comp_id.txt");
        if (compid_file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            while (!compid_file.atEnd()) {
                QString str = compid_file.readLine();
                if (str.length() > 8 && str[0] != '#') {
                    QString id_ver = str.mid(5, 2);
                    DWORD dwIdVer = id_ver.toInt(nullptr, 16);
                    QString description = str.mid(8+1);
                    compid_description.insert(dwIdVer, description);
                }
            }
        }
    }

    QString idToString(WORD id) {
        switch (id) {
        case 0x000a:case 0x0015:case 0x001c:case 0x005f:case 0x006d:case 0x0083:case 0x00aa:case 0x00ce:case 0x00e0:
            return "[ C ]";
        case 0x000f:case 0x0040:case 0x007d:case 0x0095:case 0x009e:case 0x00cd:case 0x00df:
            return "[ASM]";
        case 0x000b:case 0x0016:case 0x001d:case 0x0060:case 0x006e:case 0x00ab:case 0x00cf:case 0x00e1:case 0x0105:case 0x0109:
            return "[C++]";
        case 0x000d:case 0x0004:case 0x003d:case 0x005a:case 0x0078:case 0x0091:case 0x009d:case 0x00cc:case 0x00de:case 0x0102:
            return "[LNK]";
        case 0x003f:case 0x005c:case 0x007a:case 0x0092:case 0x009b:case 0x00ca:case 0x00dc:
            return "[EXP]";
        case 0x000e:case 0x0006:case 0x0045:case 0x005e:case 0x007c:case 0x0094:case 0x0097:case 0x009a:case 0x00c9:case 0x00db:case 0x00ff:
            return "[RES]";
        case 0x0002:case 0x0019:case 0x005d:case 0x007b:case 0x0093:case 0x009c:case 0x00cb:case 0x00dd:
            return "[IMP]";
        case 0x0009:
            return "[BAS]";
        case 0x0000:case 0x0001:
            return "[---]";
        }
        return "[" + WORDToString(id) +"]";
    }
public:
    static CompId& getInstance() {
        static CompId instance;
        return instance;
    }
    QString getDescription(WORD id, WORD ver) {
        DWORD rich_data = (id << 16) | ver;
        if (compid_description.count(rich_data) == 0) {
            return idToString(id) + " build " + QString::number(ver);
        }
        return compid_description[rich_data];
    }
};

#define COMPID (CompId::getInstance())

#endif // COMP_ID_H
