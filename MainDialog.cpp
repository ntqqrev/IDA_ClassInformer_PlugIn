
// Main Dialog
#include "stdafx.h"
#include "MainDialog.h"
#ifdef SPECIAL_EDITION
#include "AnimBannerWidget.h"
#endif

#include <QtWidgets/QDialogButtonBox>


MainDialog::MainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t animSwitch) : QDialog(QApplication::activeWindow())
{
    Ui::MainCIDialog::setupUi(this);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
    buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);

    #define INITSTATE(obj,state) obj->setCheckState((state == TRUE) ? Qt::Checked : Qt::Unchecked);
    INITSTATE(checkBox1, optionPlaceStructs);
    INITSTATE(checkBox2, optionProcessStatic);
    INITSTATE(checkBox3, optionAudioOnDone);
    #undef INITSTATE

    // Apply style sheet
    QFile file(QT_RES_PATH "style.qss");
    if (file.open(QFile::ReadOnly | QFile::Text))
        setStyleSheet(QTextStream(&file).readAll());

	this->segs = &segs;
    this->setWindowTitle(QString("Class Informer %1").arg(version.c_str()));

    // TODO: Compile switch the animated banner code in. So for a private version it's there, for the public version it's not.
    // And for the private version have a switch to "run()" to not show the banner.

    // Setup banner widget static or animated
	QRect bannerGeometry(0, 0, 292, 74);
    QWidget *bannerWidget = NULL;

    #ifdef SPECIAL_EDITION
    #pragma message(__LOC2__ "    >> Special edition build <<")
	if (animSwitch != 2)
    {
		// Instance the animated version of the banner
		bannerWidget = new AnimBannerWidget(this, animSwitch == 1);
	}    
	else 
    #endif
    {
		// Create the static banner (QLabel)
		QLabel *image = new QLabel(this);
		image->setObjectName(QString::fromUtf8("image"));
		image->setPixmap(QPixmap(QString::fromUtf8(":/res/banner.png")));
		image->setTextFormat(Qt::PlainText);
		image->setTextInteractionFlags(Qt::NoTextInteraction);
        #if QT_CONFIG(tooltip)
		image->setToolTip(QString::fromUtf8(""));
        #endif
		bannerWidget = image;
	}    
	bannerWidget->setGeometry(bannerGeometry);  
}

// On choose segments
void MainDialog::segmentSelect()
{
	SegSelect::select(*this->segs, (SegSelect::DATA_HINT | SegSelect::RDATA_HINT), "Choose segments to scan");
}

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, __out SegSelect::segments &segs, qstring &version, size_t animSwitch)
{
	BOOL result = TRUE;
    MainDialog *dlg = new MainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone, segs, version, animSwitch);
    if (dlg->exec())
    {
        #define CHECKSTATE(obj,var) var = dlg->obj->isChecked()
        CHECKSTATE(checkBox1, optionPlaceStructs);
        CHECKSTATE(checkBox2, optionProcessStatic);
        CHECKSTATE(checkBox3, optionAudioOnDone);
        #undef CHECKSTATE
		result = FALSE;
    }
	delete dlg;
    return(result);
}