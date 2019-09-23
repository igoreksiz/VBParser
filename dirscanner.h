#ifndef DIRSCANNER_H
#define DIRSCANNER_H

#include <QDialog>
#include <QThread>

namespace Ui {
class dirscanner;
}

class dirscanner : public QDialog
{
    Q_OBJECT
    volatile bool bStop;
    QThread scannerThread;
public:
    explicit dirscanner(QWidget *parent = 0);
    ~dirscanner();

private slots:
    void on_cancelButton_clicked();

private:
    Ui::dirscanner *ui;
};

#endif // DIRSCANNER_H
