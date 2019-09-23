#include "settings.h"
#include "ui_settings.h"
#include "vbfile.h"

settings::settings(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::settings)
{
    ui->setupUi(this);

    QList<QByteArray> codecs = QTextCodec::availableCodecs();
    qSort(codecs);
    int idx = 0;
    for (auto codec : codecs) {
        QString text_codec = QString::fromLatin1(codec);
        ui->comboBox->addItem(text_codec);
        if (text_codec == "CP1251")
            idx = ui->comboBox->count() - 1;
    }
    ui->comboBox->setCurrentIndex(idx);
}

settings::~settings()
{
    delete ui;
}

qint64 settings::getOptions() {
    qint64 options = 0;
    if (ui->checkBox_ShowResdescrtblLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_DETECT_BY_RAW_SEARCH;
    if (ui->checkBox_OptimizeLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_OPTIMIZE_LEAKS;
    //
    if (ui->checkBox_addCompilerLeftovers->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_COMPILER_LEFTOVERS;
    if (ui->checkBox_addRich->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_RICH;
    if (ui->checkBox_MethodNames->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_METHOD_NAMES;
    if (ui->checkBox_ObjectNames->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_OBJECT_NAMES;
    if (ui->checkBox_OLBPaths->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_OLB_PATH;
    if (ui->checkBox_ProjectPath->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_PROJECTPATH;
    if (ui->checkBox_Import->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_IMPORT;
    if (ui->checkBox_PeImport->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_SUMMARY_PE_IMPORT;


    //
    if (ui->checkBox_ShowComObjectLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_COM_OBJECT;
    if (ui->checkBox_ShowMethodPointersLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_METHOD_POINTERS;
    if (ui->checkBox_ShowMethodNameLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_METHOD_NAMES;
    if (ui->checkBox_ShowResourceMajorLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_RES_MAJOR;
    if (ui->checkBox_ShowResdescrtblLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_RESDESCTBL;
    if (ui->checkBox_ShowProjectPathLeak->checkState() == Qt::CheckState::Checked)
        options |= VBFile::VB_LEAK_PROJET_PATH;

    return options;
}

bool settings::getIsRecursive() {
    return ui->checkBox_Recursive->checkState();
}

QString settings::getCharset() {
    return ui->comboBox->currentText();
}

void settings::on_buttonSettingsOK_clicked()
{
    this->close();
}
