#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "common.h"
#include "settings.h"
#include "filescanner.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    //
    QThread scannerThread;
    settings* settingsDialog;
    FileScanner* scanner;
    void addFile(QString filePath, bool silent = false);
    void scanDir(QString dirPath);
protected:
    void dropEvent(QDropEvent *ev);
    void dragEnterEvent(QDragEnterEvent *ev);
public:
    explicit MainWindow(QWidget *parent = 0);

    ~MainWindow();

private slots:
    void on_SettingButton_clicked();
    void on_openFileButton_clicked();
    void on_openDirButton_clicked();
    void on_cancelButton_clicked();
    //
    void closeTreeFile(QWidget* item);
    void showTreeFile(QString filePath);
    void exportTreeFile(QObject* p);
    //
    void scanUpdateTextStatus(QString message);
    void scanStarted(int xmin, int xmax);
    void scanChanged(int state);
    void scanFinished();
    void scanAddResult(QTreeWidgetItem * newFileRoot);
    void scanPrepare();

    void on_fileTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_leakMaskCheckBox_stateChanged(int arg1);
    void on_fileTree_customContextMenuRequested(const QPoint &pos);

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
