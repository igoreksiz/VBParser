#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "vbfile.h"
#include "filescanner.h"

QTreeWidgetItem* parseFile(QString filePath, qint64 options, bool bAllowMessage, QString charset) {
    VBFile* vbfile = NULL;
    try {
        vbfile = new VBFile(filePath, options, charset);
    } catch (Exception::VBFileException e) {
       // QFile::remove(filePath); // !!!
        if (bAllowMessage) {
            auto metaEnum = QMetaEnum::fromType<Exception::VBFileException>();
            QMessageBox finishMsg;
            finishMsg.setText("Error " + QString(metaEnum.valueToKey(e)) );
            finishMsg.setWindowTitle("Message");
            finishMsg.setIcon(QMessageBox::Critical);
            finishMsg.exec();
        }
        return NULL;
    }
    QTreeWidgetItem* newFileRoot = new QTreeWidgetItem();
    QFileInfo fileInfo(filePath);

    if (vbfile->isUnparsable())
        newFileRoot->setForeground(0 , QBrush(Qt::red));

    newFileRoot->setText(0, QString(fileInfo.fileName()));
    newFileRoot->setToolTip(0, filePath);
    //

    QString summary = vbfile->getSummary();

    summary = "File Path: <font color=grey>" + filePath.toHtmlEscaped() + "</font><br>" + summary;

    newFileRoot->setData(0, Qt::UserRole, summary);
    newFileRoot->setData(0, Qt::UserRole + 1, filePath);
    QVector<MemoryDisclosure*> & leaks = vbfile->getLeaks();
    for (auto leak : leaks) {
        QTreeWidgetItem* newSubItem = new QTreeWidgetItem();
        newSubItem->setText(0, leak->getName());
        newSubItem->setData(0, Qt::UserRole, (qint64)leak);
        newFileRoot->addChild(newSubItem);
    }
    delete vbfile;
    return newFileRoot;
}

QTreeWidgetItem* parseFileFromThread(QString filePath, qint64 options, QString charset) {
    return parseFile(filePath, options, false, charset);
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    settingsDialog = new settings(this);
    scanner = new FileScanner(parseFileFromThread);
    connect( &scannerThread, SIGNAL( started()), scanner, SLOT( work() ));
    connect( scanner, SIGNAL( scanChanged(int)), this, SLOT( scanChanged(int) ));
    connect( scanner, SIGNAL( scanAddResult(QTreeWidgetItem *) ), this, SLOT( scanAddResult(QTreeWidgetItem *) ) );
    connect( scanner, SIGNAL( scanStarted(int, int) ), this, SLOT( scanStarted(int, int) ) );
    connect( scanner, SIGNAL( scanFinished() ), this, SLOT( scanFinished() ) );
    connect( scanner, SIGNAL( scanPrepare() ), this, SLOT( scanPrepare() ) );
    connect( scanner, SIGNAL( scanUpdateTextStatus(QString) ), this, SLOT( scanUpdateTextStatus(QString) ) );
    //
    ui->setupUi(this);
    //
    ui->labelHexHeader->setVisible(false);
    ui->hexTableOptionsFrame->setVisible(false);
    //
    setAcceptDrops(true);
}

void MainWindow::dropEvent(QDropEvent *ev)
{
   QList<QUrl> urls = ev->mimeData()->urls();
   foreach(QUrl url, urls)
   {
       QString path = url.toLocalFile();
       if (QFileInfo(path).isDir()) {
            if (!scanner->isScanning()) {
                scanDir(path);
            }
       } else addFile(path, true);
   }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *ev)
{
   ev->accept();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_SettingButton_clicked()
{
    settingsDialog->exec();
}

void MainWindow::addFile(QString filePath, bool silent)
{
    QTreeWidgetItem* element = parseFile(filePath, settingsDialog->getOptions(), true, settingsDialog->getCharset());
    if (element) {
        scanAddResult(element);
        if (!silent) {
            QMessageBox finishMsg;
            finishMsg.setText("File was successfuly added!");
            finishMsg.setWindowTitle("Message");
            finishMsg.setIcon(QMessageBox::Information);
            finishMsg.exec();
        }
    }
}

void MainWindow::on_openFileButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(0, "Open Dialog", "", "*.*");
    if (filePath != "") {
        addFile(filePath);
    }
}

void MainWindow::scanDir(QString dirPath) {
    scannerThread.quit();
    scanner->setDir(dirPath);
    scanner->setOptions(settingsDialog->getOptions());
    scanner->setRecursive(settingsDialog->getIsRecursive());
    scanner->setCharset(settingsDialog->getCharset());
    scanner->moveToThread(&scannerThread);
    scannerThread.start();
}

void MainWindow::on_openDirButton_clicked()
{
    QString dirPath = QFileDialog::getExistingDirectory(this, "Open Directory", NULL, QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath != "") {
        scanDir(dirPath);
    }
}

void MainWindow::on_cancelButton_clicked()
{
    scanner->stop();
}

void MainWindow::scanPrepare() {
    ui->statusBar->showMessage("Calculating files count ...");
    ui->progressBar->setValue(0);
    ui->cancelButton->setEnabled(true);
    ui->openDirButton->setEnabled(false);
}

void MainWindow::scanStarted(int xmin, int xmax) {
    ui->progressBar->setMinimum(xmin);
    ui->progressBar->setMaximum(xmax - 1);
    ui->progressBar->setValue(0);
}

void MainWindow::scanUpdateTextStatus(QString state){
    ui->statusBar->showMessage(state);
}

void MainWindow::scanChanged(int state){
    ui->progressBar->setValue(state);
}

void MainWindow::scanFinished(){
    QMessageBox finishMsg;
    finishMsg.setText("Scanning complete!");
    finishMsg.setWindowTitle("Message");
    finishMsg.setIcon(QMessageBox::Information);
    finishMsg.exec();
    ui->statusBar->showMessage("");
    //
    ui->openDirButton->setEnabled(true);
    ui->cancelButton->setEnabled(false);
    //
    scannerThread.quit();
}
void MainWindow::scanAddResult(QTreeWidgetItem * newFileRoot){
    ui->fileTree->addTopLevelItem(newFileRoot);
}

void MainWindow::on_fileTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *)
{
    if (current) {
       QVariant v = current->data(0, Qt::UserRole);
       if (current->parent() != NULL) {
           ui->labelHexHeader->setVisible(true);
           ui->hexTableOptionsFrame->setVisible(true);
           MemoryDisclosure* leak = (MemoryDisclosure*)v.toULongLong();
           if (ui->leakMaskCheckBox->checkState() == Qt::CheckState::Checked) {
                ui->infoTextEdit->setHtml(leak->toMaskedHexTable());
           } else {
                ui->infoTextEdit->setHtml(leak->toHexTable());
           }
           return;
       } else {
           ui->labelHexHeader->setVisible(false);
           ui->hexTableOptionsFrame->setVisible(false);
           QString summary = v.toString();
           ui->infoTextEdit->setText(summary);
           return;
       }
    }
    ui->infoTextEdit->setText("");
}

void MainWindow::on_leakMaskCheckBox_stateChanged(int)
{
    int val = ui->infoTextEdit->verticalScrollBar()->value();
    emit ui->fileTree->currentItemChanged(ui->fileTree->currentItem(), ui->fileTree->currentItem());
    ui->infoTextEdit->verticalScrollBar()->setValue(val);
}

void deleteFileEntry(QTreeWidgetItem* root) {
    for (auto child: root->takeChildren()) {
        QVariant v = child->data(0, Qt::UserRole);
        MemoryDisclosure* leak = (MemoryDisclosure*)v.toULongLong();
        delete leak;
        delete child;
    }
    delete root;
}

QString dumpFileEntry(QTreeWidgetItem* root) {
    QVariant v = root->data(0, Qt::UserRole);
    QString summary = v.toString();

    QString hexDumps = "";
    for (int i = 0; i < root->childCount(); i++) {
        hexDumps += "==== " +root->child(i)->text(0) + "====<br>";
        QVariant v = root->child(i)->data(0, Qt::UserRole);
        MemoryDisclosure* leak = (MemoryDisclosure*)v.toULongLong();
        hexDumps += leak->toMaskedHexTable();
    }
    return "<br><br><br><br><br>" + summary + hexDumps;
}


void MainWindow::closeTreeFile(QWidget* p)
{
    if (p) {
        deleteFileEntry((QTreeWidgetItem *)p);
    } else {
        while (ui->fileTree->topLevelItemCount()) {
            QApplication::processEvents();
            deleteFileEntry(ui->fileTree->topLevelItem(0));
        }
    }
}

void MainWindow::showTreeFile(QString filePath)
{
    ShowInExplorer(filePath);
}

void MainWindow::exportTreeFile(QObject* p)
{
    QString reportData = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>VB Parser Report</title></head><body>";
    if (p) {
        reportData = dumpFileEntry((QTreeWidgetItem *)p);
    } else {
        for (int i = 0 ; i < ui->fileTree->topLevelItemCount(); i++) {
            QApplication::processEvents();
            reportData += dumpFileEntry(ui->fileTree->topLevelItem(i));
        }
    }
    reportData += "</body></html>";
    QString saveReportPath = QFileDialog::getSaveFileName(this, "Save report", NULL, "HTML Page (*.html)");
    if (saveReportPath != "") {
        QFile report(saveReportPath);
        report.open(QFile::WriteOnly);
        report.write(reportData.toUtf8());
    }
}

void MainWindow::on_fileTree_customContextMenuRequested(const QPoint &pos)
{
    QTreeWidgetItem *item = ui->fileTree->itemAt(pos);
    QMenu menu(this);
    QSignalMapper* signalMapper = new QSignalMapper(this);
    if (item) {
        while (item->parent()) item = item->parent();
        //
        QAction* closeAction = new QAction("Close", this);
        connect(closeAction, SIGNAL(triggered()), signalMapper, SLOT(map()));
        signalMapper->setMapping(closeAction, (QWidget *)item);
        menu.addAction(closeAction);
        //
        QString filePath = item->data(0, Qt::UserRole + 1).toString();
        QAction* showAction = new QAction("Show in Explorer", this);
        connect(showAction, SIGNAL(triggered()), signalMapper, SLOT(map()));
        signalMapper->setMapping(showAction, filePath);
        menu.addAction(showAction);
        //
        QAction* exportAction = new QAction("Export", this);
        connect(exportAction, SIGNAL(triggered()), signalMapper, SLOT(map()));
        signalMapper->setMapping(exportAction, (QObject *)item);
        menu.addAction(exportAction);

        menu.addSeparator();
    }

    QAction* closeAll = new QAction("Close All", this);
    connect(closeAll, SIGNAL(triggered()), signalMapper, SLOT(map()));
    signalMapper->setMapping(closeAll, (QWidget *)NULL);
    menu.addAction(closeAll);

    QAction* exportAll = new QAction("Export All", this);
    connect(exportAll, SIGNAL(triggered()), signalMapper, SLOT(map()));
    signalMapper->setMapping(exportAll, (QObject *)NULL);
    menu.addAction(exportAll);

    connect(signalMapper, SIGNAL(mapped(QString)), this, SLOT(showTreeFile(QString)));
    connect(signalMapper, SIGNAL(mapped(QWidget *)), this, SLOT(closeTreeFile(QWidget *)));
    connect(signalMapper, SIGNAL(mapped(QObject *)), this, SLOT(exportTreeFile(QObject *)));

    QPoint pt(pos);
    menu.exec(ui->fileTree->mapToGlobal(pos));
}
