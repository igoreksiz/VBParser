#include "common.h"

void appendColorText(QString& result, QString text, QString color = "") {
    if (color == "")
        result += text;
    else
        result += QString("<font color=%1>%2</font>").arg(color, text);
}

QString buildHexTableMask(const unsigned char* pBuffer, QVector<BYTE> mask, BYTE bGoodMask, bool Questions) {
    QString text = "";
    const size_t BlockSize = 16;
    qint32 pos = 0;
    while (pos < mask.size()) {
        QString HexPart = "";
        QString CharPart = "";
        QString s = "";
        appendColorText(text, s.sprintf("%08x", pos) + ": ", "blue");
        for (qint64 i = 0; i < BlockSize; i++) {
            unsigned char b = pBuffer[pos + i];
            if (i == BlockSize / 2)
                appendColorText(text, " ");
            if (pos + i < mask.size()) {
                if (Questions && mask[pos + i] != bGoodMask)
                    appendColorText(text, "?? ", "gray");
                else if (mask[pos + i] == bGoodMask)
                    appendColorText(text, s.sprintf("%02X ", b));
                else
                    appendColorText(text, s.sprintf("%02X ", b), "gray");
            } else {
                appendColorText(text, "   ");
            }
        }
        appendColorText(text, "&nbsp;");
        for (qint64 i = 0; i < BlockSize; i++) {
            unsigned char b = pBuffer[pos + i];
            if (pos + i < mask.size()) {
                if (Questions && mask[pos + i] != bGoodMask)
                    appendColorText(text, "?", "gray");
                else if (mask[pos + i] == bGoodMask)
                    appendColorText(text, s.sprintf("%c", 0x20 <= b && b <= 0x7E ? b: ' ').toHtmlEscaped());
                else
                    appendColorText(text, s.sprintf("%c", 0x20 <= b && b <= 0x7E ? b: ' ').toHtmlEscaped(), "gray");
            } else {
                appendColorText(text, " ");
            }
        }
        appendColorText(text, "<br>");
        pos += BlockSize;
    }
    return "<pre><font face=\"Courier new\" color=black>" + text + "</font></pre>";
}

QString DWORDToString(DWORD n) {
    QString s;
    s.sprintf("%08x", n);
    return s;
}

QString WORDToString(WORD n) {
    QString s;
    s.sprintf("%04x", n);
    return s;
}

QString buildHexTable(const unsigned char* pBuffer, unsigned int Size) {
    QVector<BYTE> mask(Size);
    BYTE bGoodMask = 'x';
    for (qint64 i = 0; i<Size; i++)
        mask[i] = bGoodMask;
    return buildHexTableMask(pBuffer, mask, bGoodMask);
}

void ShowInExplorer(QString path) {
    QStringList args;
    args << "/select," << QDir::toNativeSeparators(path);
    QProcess *process = new QProcess();
    process->start("explorer.exe", args);
}

QString uuidToString(UUID* pUuid) {
    return QUuid::fromRfc4122(QByteArray((char*)pUuid, sizeof(*pUuid))).toString();
}
