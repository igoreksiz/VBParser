#include "vb5_6.h"

BOOL RESDESCFLAGS__HasResource(RESDESCFLAGS pflags) {
    RESDESCFLAGS bBaseType = pflags & 0xF;
    return bBaseType == 1 || bBaseType == 2 || bBaseType == 3 || pflags & 0x60;
}

tagSAFEARRAY * RESDESC__Psa(RESDESC *presdesc) {
    tagSAFEARRAY *result;
    result = (tagSAFEARRAY*)&presdesc->var.Type5.SaBase1;
    if (presdesc->var.Type5.wType2 & 0x60)
        result = (tagSAFEARRAY*)&presdesc->var.Type5.SaBase2;
    return result;
}

size_t RESDESC__CbSize(RESDESC *presdesc) {
    DWORD tmp;
    DWORD dims;
    WORD features;
    tagSAFEARRAY * psa;

    switch (presdesc->wTypeFlags & 0xF) {
        case 1:
        case 2:
        case 3:
        case 0xB:
            if (!(presdesc->wTypeFlags & 0x2000))
                return 4 + ((presdesc->wTypeFlags & 0x0400) ? 2 : 0);
            return 4 + 4;
        case 4:
        case 0xA:
            return 4 + 6;
        case 5:
            if (presdesc->wTypeFlags & 0x0100) {
                if (presdesc->var.Type5.wType2 & 0x60) {
                    return 4 + 28;
                } else {
                    tmp = -((presdesc->var.Type5.wType2 & 0xF) != 0xA);
                    tmp &= 0xFC;
                    return 4 + 10 + tmp;
                }
            } else if (RESDESCFLAGS__HasResource(presdesc->var.Type5.wType2) || !(presdesc->wTypeFlags & 0x80) || presdesc->wTypeFlags & 0x2200) {
                psa = RESDESC__Psa(presdesc);
                dims = psa->cDims;
                features = psa->fFeatures;
                return 4 + (dims > 0 ? 8 * dims - 8 : 0) + ((features & 0xE0) != 0 ? 4 : 0) + ((presdesc->var.Type5.wType2 & 0x60) ? 52 : 36);
            }
            return 0;
        case 6:
            return 4 + ((presdesc->wTypeFlags & 0x0400) ? 2 : 3);
        case 8:
            return 4 + 2;
        case 9:
            return 4 + 24;
    }
    return 0;
}
