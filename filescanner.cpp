#include "filescanner.h"

void FileScanner::scanPath(QDir path) {
    QFileInfoList files = path.entryInfoList(QDir::NoDotAndDotDot | QDir::AllEntries);
    foreach (QFileInfo file, files){
        if (bStop)
            return;
        if (file.isDir() && bRecursive)
            scanPath(QDir(file.filePath()));
        if (file.isFile())
        {
            emit scanUpdateTextStatus(file.filePath());
            QTreeWidgetItem* element = callback(file.filePath(), options, charset);
            if (element) emit scanAddResult(element);
            if ((int)((iProgress + 1) * 100.0 / iFilesToScan)  != (int)(iProgress * 100.0/ iFilesToScan))
                emit scanChanged(iProgress);
            iProgress++;
        }
    }
}

size_t FileScanner::countFiles(QDir path) {
    size_t result = 0;
    QFileInfoList files = path.entryInfoList(QDir::NoDotAndDotDot | QDir::AllEntries);
    foreach (QFileInfo file, files){
        if (bStop)
            break;
        if (file.isDir() && bRecursive)
            result += countFiles(QDir(file.filePath()));
        else
            if (file.isFile()) result++;
    }
    return result;
}

void FileScanner::setRecursive(bool bRecursive)
{
    this->bRecursive = bRecursive;
}

void FileScanner::setCharset(QString charset)
{
    this->charset = charset;
}

void FileScanner::work() {
    this->bStop = false;
    emit scanPrepare();
    this->iFilesToScan = countFiles(dirPath);
    emit scanStarted(0, iFilesToScan);
    this->iProgress = 0;
    scanPath(dirPath);
    emit scanFinished();
    this->bStop = true;
}

FileScanner::FileScanner(scannerCallback_t callback) : callback(callback), bStop(true), bRecursive(true) { }

void FileScanner::setOptions(qint64 options)
{
    this->options = options;
}

void FileScanner::setDir(QString dirPath) {
    this->dirPath = QDir(dirPath);
}

void FileScanner::stop() {
    this->bStop = true;
}

bool FileScanner::isScanning() {
    return !bStop;
}

FileScanner::~FileScanner() {

}

