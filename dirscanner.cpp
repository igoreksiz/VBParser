#include "dirscanner.h"
#include "ui_dirscanner.h"

dirscanner::dirscanner(QWidget *parent, QString dirPath) :
    QDialog(parent),
    ui(new Ui::dirscanner)
{
    bStop = false;

    ui->setupUi(this);
}

dirscanner::~dirscanner()
{
    delete ui;
}

void dirscanner::on_cancelButton_clicked()
{
    ui->cancelButton->setEnabled(false);
    bStop = true;
}
