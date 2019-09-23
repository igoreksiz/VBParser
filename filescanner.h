#ifndef FILESCANNER_H
#define FILESCANNER_H

#include "common.h"

typedef QTreeWidgetItem* (*scannerCallback_t) (QString, qint64, QString);

class FileScanner : public QObject
{
    Q_OBJECT
private:
    scannerCallback_t callback;
    volatile bool bStop;
    bool bRecursive;
    QString charset;
    QDir dirPath;
    size_t iFilesToScan;
    size_t iProgress;
    qint64 options;
    //
    void scanPath(QDir dirPath);
    size_t countFiles(QDir dirPath);
public slots:
    void work();
public:
    FileScanner(scannerCallback_t callback);
    void setRecursive(bool bRecoursive);
    void setCharset(QString charset);
    void setDir(QString dirPath);
    void stop();
    void setOptions(qint64 options);
    bool isScanning();
    ~FileScanner();
signals:
   void scanStarted(int xmin, int xmax);
   void scanChanged(int state);
   void scanUpdateTextStatus(QString message);
   void scanFinished();
   void scanAddResult(QTreeWidgetItem* newFileRoot);
   void scanPrepare();
};

#endif // FILESCANNER_H
