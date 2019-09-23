#ifndef SETTINGS_H
#define SETTINGS_H

#include "common.h"

namespace Ui {
class settings;
}

class settings : public QDialog
{
    Q_OBJECT

public:
    explicit settings(QWidget *parent = 0);

    bool getIsRecursive();
    qint64 getOptions();
    QString getCharset();
    ~settings();

private slots:
    void on_buttonSettingsOK_clicked();



private:
    Ui::settings *ui;
};

#endif // SETTINGS_H
