#include "vbfile.h"

void VBFile::ParseLeak_RESDESCTBL(RESDESCTBL* pResDscrTbl, QString strType) {
    if (pResDscrTbl->wTotalBytes <= offsetof(RESDESCTBL, resdesc))
        return; // header only

    if (resdscrtbl_checked.find(pResDscrTbl) != resdscrtbl_checked.end())
        return;
    resdscrtbl_checked.insert(pResDscrTbl);

    RESDESC* presdesc = &pResDscrTbl->resdesc;
    while ((PBYTE)presdesc < (PBYTE)pResDscrTbl + pResDscrTbl->wTotalBytes) {
        size_t nSize = RESDESC__CbSize(presdesc);
        if (nSize < offsetof(RESDESC, var)) break;
        size_t nVarSize = nSize;
        //
        MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)presdesc, nVarSize, pFileDataEnd, " Unknown");
        leak->maskSet(0, nVarSize, MemoryDisclosure::MASK_VALID);
        if ((presdesc->wTypeFlags & 0xF) == 0x9) {
            RESDESCTBL* pSubResDescTbl = (RESDESCTBL*)vaToPointer(presdesc->var.Type9.lpSubResDscrTbl);
            if (isValidFilePointer(pSubResDescTbl, sizeof(*pSubResDescTbl))) {
                ParseLeak_RESDESCTBL(pSubResDescTbl, strType + " Type9 RECURSION");
            }
            leak->maskSet(4 + 0, 2, MemoryDisclosure::MASK_LEAK);
            leak->maskSet(4 + 8, 16, MemoryDisclosure::MASK_LEAK);
            leak->setName(strType + " Type9");
        } else if (presdesc->wTypeFlags == 0x0005) {
            leak->maskSet(4 + 0, 4, MemoryDisclosure::MASK_LEAK);
            leak->maskSet(4 + 6, 6, MemoryDisclosure::MASK_LEAK);
            if (nVarSize > 4 + 38) {
                leak->maskSet(4 + 38, 2, MemoryDisclosure::MASK_LEAK);
            }
            leak->setName(strType + " Type5");
        } else {
            //
        }
        if (options & VB_LEAK_RESDESCTBL)
            addLeak(leak);
        presdesc = (RESDESC*)((PBYTE)presdesc + nSize);
    }
    //
    //Q_ASSERT((PBYTE)presdesc == (PBYTE)pResDscrTbl + pResDscrTbl->wTotalBytes);
}

void VBFile::ParseLeak_MethodNames(PDWORD pLeakBegin, PDWORD pLeakEnd) {
    DWORD dwMethodCount = pLeakEnd - pLeakBegin;
    MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)pLeakBegin, dwMethodCount * sizeof(DWORD), pFileDataEnd, "Method Name Pointers");
    leak->maskSet(0, dwMethodCount * sizeof(DWORD), MemoryDisclosure::MASK_VALID);
    for (DWORD i = 0; i < dwMethodCount; i++) {
        QString MethodName = safeReadStringVA(pLeakBegin[i]);
        if (!MethodName.isNull()) {
            if (options & VB_SUMMARY_METHOD_NAMES)
                addSummaryLine("[Method-"+QString::number(i)+"] " + MethodName);
        } else {
            leak->maskSet(i * sizeof(DWORD), sizeof(DWORD), MemoryDisclosure::MASK_LEAK);
        }
    }
    if (options & VB_LEAK_METHOD_NAMES)
        addLeak(leak);
}

void VBFile::ParseLeak_ProjectPath(WCHAR* wsProjectPath, qint64 sizeOfProjectPath) {
    QString ProjectPath = safeReadWideString(wsProjectPath, sizeOfProjectPath / sizeof(WCHAR));
    if (options & VB_SUMMARY_PROJECTPATH)
        addSummaryLine("[VB] ProjectPath = " + safeReadWideString(wsProjectPath, sizeOfProjectPath / sizeof(WCHAR) ));
    qint64 len = ProjectPath.length() * sizeof(WCHAR);
    MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)wsProjectPath, sizeOfProjectPath, pFileDataEnd, "ProjectPath");
    leak->maskSet(0, sizeOfProjectPath, MemoryDisclosure::MASK_LEAK);
    leak->maskSet(0, (len + 1) * sizeof(WCHAR), MemoryDisclosure::MASK_VALID);
    if (options & VB_LEAK_PROJET_PATH)
        addLeak(leak);
}

void VBFile::ParseLeak_lpMethods(DWORD lpObjectInfo, PDWORD pdwMethods, WORD wMethodCount) {
    MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)pdwMethods, wMethodCount * sizeof(DWORD), pFileDataEnd, "Methods Pointers Array");
    leak->maskSet(0, wMethodCount * sizeof(DWORD), MemoryDisclosure::MASK_VALID);
    for (DWORD i = 0; i < wMethodCount; i++) {
        pVB_Method pMethod = (pVB_Method)vaToPointer(pdwMethods[i]);
        if (isValidFilePointer(pMethod, sizeof(*pMethod)) && pMethod->lpObjectInfo == lpObjectInfo) {
            //addSummaryLine("[Good method at " + DWORDToString(pdwMethods[i]));
            //
        } else {
            leak->maskSet(i * sizeof(DWORD), sizeof(DWORD), MemoryDisclosure::MASK_LEAK);
        }
    }
    if (options & VB_LEAK_METHOD_POINTERS)
        addLeak(leak);
}

void VBFile::ParseLeak_Objects(pVB_PublicObjectDescr pObjectArray, DWORD dwObjectCount) {
    QSet<DWORD> controlUuids;
    QSet<PVOID> knownControlUuidReferenses;

    pVB_PublicObjectDescr pObject = pObjectArray;
    PDWORD pMethodNameLeakBegin = NULL, pMethodNameLeakEnd = NULL;
    for (qint64 i = 0; i < dwObjectCount; i++, pObject++) {
        // ObjectName
        QString ObjectName = safeReadStringVA(pObject->lpszObjectName);

        if (options & VB_SUMMARY_OBJECT_NAMES)
            addSummaryLine("[Object-"+QString::number(i)+"]: " + ObjectName);

        RESDESCTBL* pPublicBytes = (RESDESCTBL*)vaToPointer(pObject->lpPublicBytes);
        if (isValidFilePointer(pPublicBytes, sizeof(*pPublicBytes))) {
            ParseLeak_RESDESCTBL(pPublicBytes, "PublicBytes RESDESCTBL");
        }
        RESDESCTBL* pStaticBytes = (RESDESCTBL*)vaToPointer(pObject->lpStaticBytes);
        if (isValidFilePointer(pStaticBytes, sizeof(*pStaticBytes))) {
            ParseLeak_RESDESCTBL(pStaticBytes, "StaticBytes RESDESCTBL");
        }
        // MethodNames Table LEAK
        PDWORD pdwMethodNames = (PDWORD)vaToPointer(pObject->lpMethodNames);
        PDWORD pdwMethodNamesEnd = pdwMethodNames + pObject->dwMethodCount;
        if (isValidFilePointer(pdwMethodNames, pObject->dwMethodCount * sizeof(DWORD)) && pObject->dwMethodCount) {
            if (pMethodNameLeakBegin)
                pMethodNameLeakBegin = min(pdwMethodNames, pMethodNameLeakBegin);
            else
                pMethodNameLeakBegin = pdwMethodNames;
            //
            if (pMethodNameLeakEnd)
                pMethodNameLeakEnd = max(pdwMethodNamesEnd, pMethodNameLeakBegin);
            else
                pMethodNameLeakEnd = pdwMethodNamesEnd;
        }
        // Object Info
        pVB_ObjectInfo pObjectInfo = (pVB_ObjectInfo)vaToPointer(pObject->lpObjectInfo);
        if (isValidFilePointer(pObjectInfo, sizeof(*pObjectInfo))) {
            if (options & VB_SUMMARY_COMPILER_LEFTOVERS) {
                addSummaryLine("[Compiler Leftover]: "+ObjectName+" lpIdeData = 0x" + DWORDToString(pObjectInfo->lpIdeData));
                addSummaryLine("[Compiler Leftover]: "+ObjectName+" lpIdeData2 = 0x" + DWORDToString(pObjectInfo->lpIdeData2));
                addSummaryLine("[Compiler Leftover]: "+ObjectName+" lpIdeData3 = 0x" + DWORDToString(pObjectInfo->lpIdeData3));
            }

            PDWORD pdwMethods = (PDWORD)vaToPointer(pObjectInfo->lpMethods);
            if (isValidFilePointer(pdwMethods, sizeof(DWORD) * pObjectInfo->wMethodCount)) {
                ParseLeak_lpMethods(pObject->lpObjectInfo, pdwMethods, pObjectInfo->wMethodCount);
            } else {
                if (options & VB_SUMMARY_COMPILER_LEFTOVERS)
                    addSummaryLine("[Compiler Leftover]: "+ObjectName+" lpMethods = 0x" + DWORDToString(pObjectInfo->lpMethods));
            }
            if ((pObject->fObjectType & 0x02) == 0x02) {
                pVB_OptionalObjectInfo pOptionalObjectInfo = (pVB_OptionalObjectInfo)((PBYTE)pObjectInfo + sizeof(*pObjectInfo));
                if (pOptionalObjectInfo->dwControlCount) {
                    if (options & VB_SUMMARY_COMPILER_LEFTOVERS)
                        addSummaryLine("[Compiler Leftover]: "+ObjectName+" optional lpIdeData = 0x" + DWORDToString(pOptionalObjectInfo->lpIdeData));
                    pVB_ControlInfo pControl = (pVB_ControlInfo)vaToPointer(pOptionalObjectInfo->lpControls);
                    if (isValidFilePointer(pControl, sizeof(*pControl) * pOptionalObjectInfo->dwControlCount)) {
                        for (DWORD k = 0; k < pOptionalObjectInfo->dwControlCount; k++, pControl++) {
                            QString ControlName = safeReadStringVA(pControl->lpszName);
                            if (options & VB_SUMMARY_COMPILER_LEFTOVERS)
                                addSummaryLine("[Compiler Leftover]: "+ObjectName+" "+ControlName+" lpIdeData = 0x" + DWORDToString(pControl->lpIdeData));
                            UUID* pControlUUID = (UUID*)vaToPointer(pControl->lpGuid);
                            if (isValidFilePointer(pControlUUID, sizeof(UUID))) {
                                controlUuids.insert(pControl->lpGuid);
                                knownControlUuidReferenses.insert(&pControl->lpGuid);
                            }
                        }
                    }
                }
            }
        }
    }
    if (pMethodNameLeakBegin && pMethodNameLeakEnd) {
        ParseLeak_MethodNames(pMethodNameLeakBegin, pMethodNameLeakEnd);
    }


    QSet<pVB_OLB_Info> OLB_List;
    for (auto pUuid : controlUuids) {
        QSet<PVOID> refs = findPattern((PBYTE)&pUuid, sizeof(DWORD));
        QSet<PVOID> new_refs = refs - knownControlUuidReferenses;
        for (auto x : new_refs) {
            pVB_OLB_Header pOlbHeader = (pVB_OLB_Header)CONTAINING_RECORD(x, VB_OLB_Header, lpUuid);
            pVB_OLB_Info pOlbInfo = (pVB_OLB_Info)vaToPointer(pOlbHeader->lpInfo);
            if (isValidFilePointer(pOlbInfo, sizeof(*pOlbInfo))) {
                OLB_List.insert(pOlbInfo);
            }
        }
    }
    for (auto pOlbInfo : OLB_List) {
        if (options & VB_SUMMARY_OLB_PATH) {
            addSummaryLine(QString("[OLB]: ") +
                           "Name=<" +
                           safeReadStringVA(pOlbInfo->pszName) +
                           "> Path=<" +
                           safeReadStringVA(pOlbInfo->pszPath) +
                           ">");
        }
    }
}

void VBFile::ParseLeak_COMObject(pVB_ComRegData pComRegData) {
    MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)pComRegData, sizeof(*pComRegData), pFileDataEnd, "COM Object");
    leak->maskSet(0, sizeof(*pComRegData), MemoryDisclosure::MASK_VALID);
    if (pComRegData->bSZProjectName) {
        QString ProjectName = safeReadString((PCHAR)pComRegData->bSZProjectName);
        addSummaryLine("[VB COM] ProjectName: " + ProjectName);
        leak->visualBasicMaskString(pComRegData->bSZProjectName);
    }
    if (pComRegData->bSZProjectDescription) {
        QString ProjectDescription = safeReadString((PCHAR)pComRegData->bSZProjectDescription);
        addSummaryLine("[VB COM] ProjectDescription: " + ProjectDescription);
        leak->visualBasicMaskString(pComRegData->bSZProjectDescription);
    }
    if (pComRegData->bSZHelpDirectory) {
        QString HelpDirectory = safeReadString((PCHAR)pComRegData->bSZHelpDirectory);
        addSummaryLine("[VB COM] HelpDirectory: " + HelpDirectory);
        leak->visualBasicMaskString(pComRegData->bSZHelpDirectory, false);
    }
    if (pComRegData->bRegInfo) {
        DWORD dwComRegInfo = pComRegData->bRegInfo;
        pVB_ComRegInfo pComRegInfo = (pVB_ComRegInfo)((PBYTE)pComRegData + dwComRegInfo);
        while (isValidFilePointer(pComRegInfo, sizeof(*pComRegInfo))) {
            leak->maskSet(dwComRegInfo, sizeof(*pComRegInfo), MemoryDisclosure::MASK_VALID); // header
            //
            if (pComRegInfo->fObjectType != 0x10 && pComRegInfo->fObjectType != 0x2) {// better condition for this leak?
                leak->maskSet(dwComRegInfo + offsetof(VB_ComRegInfo, dwMiscStatus),
                    sizeof(pComRegInfo->dwMiscStatus),
                    MemoryDisclosure::MASK_LEAK);
                leak->maskSet(dwComRegInfo + offsetof(VB_ComRegInfo, wToolboxBitmap32),
                    sizeof(pComRegInfo->wToolboxBitmap32),
                    MemoryDisclosure::MASK_LEAK);
            } else {
                leak->maskSet(dwComRegInfo + offsetof(VB_ComRegInfo, dwMiscStatus),
                    sizeof(pComRegInfo->dwMiscStatus),
                    MemoryDisclosure::MASK_VALID);
                leak->maskSet(dwComRegInfo + offsetof(VB_ComRegInfo, wToolboxBitmap32),
                    sizeof(pComRegInfo->wToolboxBitmap32),
                    MemoryDisclosure::MASK_VALID);
            }
            leak->maskSet(dwComRegInfo + offsetof(VB_ComRegInfo, wDefaultIcon),
                sizeof(pComRegInfo->wDefaultIcon),
                MemoryDisclosure::MASK_LEAK); // any condition for this leak?
            //
            if (iVBVersion == 5) { // better rule?
                leak->maskSet(
                    dwComRegInfo + offsetof(VB_ComRegInfo, fIsDesigner),
                    sizeof(pComRegInfo->fIsDesigner),
                    MemoryDisclosure::MASK_LEAK);
            }
            if (iVBVersion == 5 || pComRegInfo->fIsDesigner == 0) {
                leak->maskSet(
                    dwComRegInfo + offsetof(VB_ComRegInfo, bDesignerData),
                    sizeof(pComRegInfo->bDesignerData),
                    MemoryDisclosure::MASK_LEAK);
            } else {
                if (pComRegInfo->fIsDesigner != 0) {
                    pVB_ComDesigner pVBDesigner = (pVB_ComDesigner)((PBYTE)pComRegData + pComRegInfo->bDesignerData);
                    leak->maskSet(pComRegInfo->bDesignerData,
                        sizeof(*pVBDesigner),
                        MemoryDisclosure::MASK_VALID);
                    if (isValidFilePointer(pVBDesigner, sizeof(*pVBDesigner))
                            && isValidFilePointer(&pVBDesigner->base, pVBDesigner->cbStructSize)) {
                        leak->maskSet(pComRegInfo->bDesignerData + offsetof(VB_ComDesigner, base),
                            pVBDesigner->cbStructSize,
                            MemoryDisclosure::MASK_VALID);
                        //
                        PBSTR pbstrAddinRegKey = (PBSTR)&pVBDesigner->base;
                        QString AddinRegKey = safeReadString(pbstrAddinRegKey->str, min(pbstrAddinRegKey->len, 256));
                        addSummaryLine("[VB COM Designer] AddinRegKey: " + AddinRegKey);
                        //
                        PBSTR pbstrAddinName = (PBSTR)BSTR_SKIP(pbstrAddinRegKey);
                        QString AddinName = safeReadString(pbstrAddinName->str, min(pbstrAddinName->len, 256));
                        addSummaryLine("[VB COM Designer] AddinName: " + AddinName);
                        //
                        PBSTR pbstrAddinDescription = (PBSTR)BSTR_SKIP(pbstrAddinName);
                        QString AddinDescription = safeReadString(pbstrAddinDescription->str, min(pbstrAddinDescription->len, 256));
                        addSummaryLine("[VB COM Designer] AddinDescription: " + AddinDescription);
                        //
                        PDWORD pdwLoadBehaviour = (PDWORD)BSTR_SKIP(pbstrAddinDescription);
                        //
                        PBSTR pbstrSatelliteDll = (PBSTR)((PBYTE)pdwLoadBehaviour + sizeof(*pdwLoadBehaviour));
                        QString SatelliteDll = safeReadString(pbstrSatelliteDll->str, min(pbstrSatelliteDll->len, 256));
                        addSummaryLine("[VB COM Designer] SatelliteDll: " + SatelliteDll);
                        //
                        PBSTR pbstrAdditionalRegKey = (PBSTR)BSTR_SKIP(pbstrSatelliteDll);
                        QString AdditionalRegKey = safeReadString(pbstrAdditionalRegKey->str, min(pbstrAdditionalRegKey->len, 256));
                        addSummaryLine("[VB COM Designer] AdditionalRegKey: " + AdditionalRegKey);
                        //
                        PDWORD pdwCommandLineSafe = (PDWORD)BSTR_SKIP(pbstrAdditionalRegKey);
                        //
                        // TODO: Addin data parser
                    } else {
                        addSummaryLineWarning("[VB COM] Invalid bDesignerData: " + DWORDToString(pComRegInfo->bDesignerData));
                    }
                }
            }
            if (pComRegInfo->fIsInterface == 0) {
                leak->maskSet(
                    dwComRegInfo + offsetof(VB_ComRegInfo, bUuidObjectIFace),
                    sizeof(pComRegInfo->bUuidObjectIFace),
                    MemoryDisclosure::MASK_LEAK); // untested
            } else if (pComRegInfo->bUuidObjectIFace) {
                leak->maskSet(
                    pComRegInfo->bUuidObjectIFace,
                    sizeof(UUID),
                    MemoryDisclosure::MASK_VALID);
            }
            if (pComRegInfo->fHasEvents != 0 && pComRegInfo->bUuidEventsIFace) {
                leak->maskSet(
                    pComRegInfo->bUuidEventsIFace,
                    sizeof(UUID),
                    MemoryDisclosure::MASK_VALID);
            }
            if (pComRegInfo->bObjectDescription)
                leak->visualBasicMaskString(pComRegInfo->bObjectDescription, false);
            if (pComRegInfo->bObjectName)
                leak->visualBasicMaskString(pComRegInfo->bObjectName);
            if (!pComRegInfo->bNextObject) // is last object?
                break;
            dwComRegInfo = pComRegInfo->bNextObject;
            pComRegInfo = (pVB_ComRegInfo)((PBYTE)pComRegData + dwComRegInfo);
        }
    }
    if (options & VB_LEAK_COM_OBJECT)
        addLeak(leak);
}

void VBFile::readVB56Structures() {
    addSummaryLine("[VB] RuntimeBuild = " + QString::number(pVBHeader->wRuntimeBuild));
    addSummaryLine("[VB] RuntimeRevision = " + QString::number(pVBHeader->wRuntimeRevision));
    QString ProjectDescription;
    if (pVBHeader->bSZProjectDescription) {
        ProjectDescription = safeReadString((PCHAR)pVBHeader + pVBHeader->bSZProjectDescription);
        addSummaryLine("[VB] ProjectDescription: " + ProjectDescription);
    }
    QString ProjectExeName;
    if (pVBHeader->bSZProjectExeName) {
        ProjectExeName = safeReadString((PCHAR)pVBHeader + pVBHeader->bSZProjectExeName);
        addSummaryLine("[VB] ProjectExeName: " + ProjectExeName);
    }
    QString ProjectHelpFile;
    if (pVBHeader->bSZProjectHelpFile) {
        ProjectHelpFile = safeReadString((PCHAR)pVBHeader + pVBHeader->bSZProjectHelpFile);
        addSummaryLine("[VB] ProjectHelpFile: " + ProjectHelpFile);
    }
    QString ProjectName;
    if (pVBHeader->bSZProjectName) {
        ProjectName = safeReadString((PCHAR)pVBHeader + pVBHeader->bSZProjectName);
        addSummaryLine("[VB] ProjectName: " + ProjectName);
    }
    QString LangId;
    if (pVBHeader->szLangDll[0] != '*')
        addSummaryLine("[VB] LangDll: " + safeReadString(pVBHeader->szLangDll));
    if (pVBHeader->szSecLangDll[0] != '~' && pVBHeader->szSecLangDll[0] != '*')
        addSummaryLine("[VB] SecLangDll: " + safeReadString(pVBHeader->szSecLangDll));
    //
    QString PrimitivePath = safeReadWideString(pProjData->wsPrimitivePath, sizeof(pProjData->wsPrimitivePath) / sizeof(WCHAR));

    if (PrimitivePath != "*\\A" && PrimitivePath != "") {
        addSummaryLineWarning("[VB] PrimitivePath: " + PrimitivePath);
    }
    ParseLeak_ProjectPath(pProjData->wsProjectPath, sizeof(pProjData->wsProjectPath));
    //
    if (pProjData->lpNativeCode == 0) {
        addSummaryLine("[VB] CompilationType=-1 'P-Code");
    } else {
        addSummaryLine("[VB] CompilationType=0 'Native");
    }
    //
    pVB_ObjectTable pObjectTable = (pVB_ObjectTable)vaToPointer(pProjData->lpObjectTable);
    if (isValidFilePointer(pObjectTable, sizeof(*pObjectTable))) {

        if (pObjectTable->dwTotalObjects != pObjectTable->dwObjectsInUse)
        addSummaryLineWarning("[VB SecoundaryProjInfo] dwTotalObjects=" + DWORDToString(pObjectTable->dwTotalObjects)
                              + " dwObjectsInUse=" + DWORDToString(pObjectTable->dwObjectsInUse));

        pVB_SecondaryProjInfo pSecondaryProjInfo = (pVB_SecondaryProjInfo)vaToPointer(pObjectTable->lpProjectInfo2);
        if (isValidFilePointer(pSecondaryProjInfo, sizeof(*pSecondaryProjInfo))) {
            addSummaryLine("[VB SecoundaryProjInof] ProjectDescription: " + safeReadStringVA(pSecondaryProjInfo->szProjectDescription));
            addSummaryLine("[VB SecoundaryProjInof] ProjectHelpFile: " + safeReadStringVA(pSecondaryProjInfo->szProjectHelpFile));
        }
        if (pVBHeader->szLangDll[0] != '*')
            addSummaryLine("[VB] LangDll: " + safeReadString(pVBHeader->szLangDll));

        pVB_PublicObjectDescr pObjectArray = (pVB_PublicObjectDescr)vaToPointer(pObjectTable->lpObjectArray);
        if (isValidFilePointer(pObjectArray, sizeof(*pObjectArray))) {
            ParseLeak_Objects(pObjectArray, pObjectTable->dwTotalObjects);
        }
    }
    PDWORD pCodeStartMarker = (PDWORD)vaToPointer(pProjData->lpCodeStart);
    if (isValidFilePointer(pCodeStartMarker, sizeof(*pCodeStartMarker))) {
        if (*pCodeStartMarker != 0xE9E9E9E9) {
            addSummaryLineWarning("[VB Warning]: Invalid code start marker: " + DWORDToString(*pCodeStartMarker));
        }
    } else {
        addSummaryLineWarning("[VB Warning]: Invalid code start marker pointer: " + DWORDToString(pProjData->lpCodeStart));
    }
    PDWORD pCodeEndMarker = (PDWORD)vaToPointer(pProjData->lpCodeEnd);
    if (isValidFilePointer(pCodeEndMarker, sizeof(*pCodeEndMarker))) {
        if (*pCodeEndMarker != 0x9E9E9E9E) {
            addSummaryLineWarning("[VB Warning]: Invalid code end marker: " + DWORDToString(*pCodeEndMarker));
        }
    } else {
        addSummaryLineWarning("[VB Warning]: Invalid code end marker pointer: " + DWORDToString(pProjData->lpCodeEnd));
    }
    pVB_ComRegData pVBCOMRegData = (pVB_ComRegData)vaToPointer(pVBHeader->lpComRegisterData);
    if (isValidFilePointer(pVBCOMRegData, sizeof(*pVBCOMRegData))) {
        ParseLeak_COMObject(pVBCOMRegData);
    }
    if (pProjData->dwExternalCount)
    {
        pVB_ExternTable pExternTable = (pVB_ExternTable)vaToPointer(pProjData->lpExternalTable);
        if (isValidFilePointer(pExternTable, sizeof(*pExternTable)))
        {
            QSet<QString> uuid_import;
            for (DWORD i = 0; i < (pProjData->dwExternalCount & 0xff); i++, pExternTable++) // LIMIT! max 256
            {
                if (pExternTable->dwType == 7) {
                    pVB_ApiImportType7 pApiImport = (pVB_ApiImportType7)vaToPointer(pExternTable->lpValue);
                    if (isValidFilePointer(pApiImport, sizeof(*pApiImport)))
                    {
                        if (options & VB_SUMMARY_IMPORT)
                                addSummaryLine(QString("IMPORT: ") +
                                               "Lib=<" +
                                               safeReadStringVA(pApiImport->lpszLibraryName) +
                                               "> Function=<" +
                                               safeReadStringVA(pApiImport->lpszImportFunction) +
                                               ">");
                    }
                } else if (pExternTable->dwType == 6) {
                    pVB_ApiImportType6 pApiImport = (pVB_ApiImportType6)vaToPointer(pExternTable->lpValue);
                    if (isValidFilePointer(pApiImport, sizeof(*pApiImport)))
                    {
                        UUID* pImportUuid = (UUID*)vaToPointer(pApiImport->lpUuid);
                        if (isValidFilePointer(pApiImport, sizeof(*pApiImport))) {
                            uuid_import.insert(uuidToString(pImportUuid));
                        }
                    }
                } else {
                    addSummaryLineWarning(QString("IMPORT: UNKNWON ") + DWORDToString(pExternTable->dwType));
                }
            }
            if (options & VB_SUMMARY_IMPORT)
                for (auto uuid : uuid_import) {
                    addSummaryLine(QString("IMPORT: ") + uuid);
                }
        }
    }
}

void VBFile::readRichSignature() {
    DWORD* pRichBlock = (DWORD*)(pFileData + sizeof(IMAGE_DOS_HEADER));
    DWORD dwRichSignatureIndex = 0;
    DWORD dwRichEncoder;
    bool isRichPresent = false;
    while (&pRichBlock[dwRichSignatureIndex + 1] < (PVOID)pNtHeaders) {
        if (pRichBlock[dwRichSignatureIndex] == RICH_SIGNATURE) {
            dwRichEncoder = pRichBlock[dwRichSignatureIndex + 1];
            isRichPresent = true;
            break;
        }
        dwRichSignatureIndex++;
    }
    if (isRichPresent) {
        bool isDansLocated = false;
        DWORD dwDansSignatureIndex = 0;
        while (dwDansSignatureIndex < dwRichSignatureIndex) {
            if (pRichBlock[dwDansSignatureIndex] == (DanS_SIGNATURE ^ dwRichEncoder)) {
                isDansLocated = true;
                break;
            }
            dwDansSignatureIndex++;
        }
        if (isDansLocated) {
            pRichBlock = &pRichBlock[dwDansSignatureIndex];
            dwRichSignatureIndex -= dwDansSignatureIndex;
            dwDansSignatureIndex = 0;
            //
            DWORD dwDosStubSize = (BYTE*)pRichBlock - pFileData;
            DWORD dwDosHeaderHash = dwDosStubSize;
            for (size_t i = 0; i < dwDosStubSize; i++) {
                if (i < offsetof(IMAGE_DOS_HEADER, e_lfanew) || i >= offsetof(IMAGE_DOS_HEADER, e_lfanew) + sizeof(pDosHeader->e_lfanew))
                    dwDosHeaderHash += ROL(pFileData[i], i & 0x1f);
            }
            if (dwRichSignatureIndex > 4) {
                DWORD* pRichData = new DWORD[dwRichSignatureIndex];
                for (DWORD i = 0; i < 4; i++)
                    pRichData[i] = pRichBlock[i] ^ dwRichEncoder;
                //
                if (pRichData[0] == DanS_SIGNATURE) {
                    if (pRichData[1] == 0 && pRichData[2] == 0 && pRichData[3] == 0) {
                        DWORD dwRichHash = 0;
                        for (DWORD i = 4; i < dwRichSignatureIndex - 1; i += 2) {
                            pRichData[i] = pRichBlock[i] ^ dwRichEncoder;
                            pRichData[i + 1] = pRichBlock[i + 1] ^ dwRichEncoder;
                            DWORD pair_hash = ROL(pRichData[i], pRichData[i + 1] & 0x1f);
                            dwRichHash += pair_hash;
                            QString desr = COMPID.getDescription(pRichData[i] >> 16, pRichData[i] & 0xffff);
                            addSummaryLine("[RICH]: " + desr + " count=" + QString::number(pRichData[i + 1], 10));
                        }
                        DWORD dwOriginalDosHeaderHash = dwRichEncoder - dwRichHash;
                        if (dwDosHeaderHash != dwOriginalDosHeaderHash) {
                            if (dwDosStubSize == dwOriginalDosHeaderHash)
                                addSummaryLineWarning("[RICH]: MSG_RICH_OLD_STYLE");
                            else
                                addSummaryLineWarning("[RICH]: MSG_RICH_DOS_HEADER_HASH_MISSMATCH " +
                                               DWORDToString(dwDosHeaderHash) + " vs " +
                                               DWORDToString(dwOriginalDosHeaderHash));
                        }
                        if (DEFAULT_MICROSOFT_DOSHEADER_HASH != dwOriginalDosHeaderHash && dwDosStubSize != dwOriginalDosHeaderHash) {
                            addSummaryLineWarning("[RICH]: MSG_RICH_NEW_DOS_HEADER_HASH hash=" +
                                           DWORDToString(dwOriginalDosHeaderHash) + " size=" +
                                           DWORDToString(dwDosStubSize));
                        }
                    } else {
                        addSummaryLineWarning("[RICH]: MSG_RICH_HEADER_CORRUPTED" + DWORDToString(pRichData[1]) + DWORDToString(pRichData[2]) + DWORDToString(pRichData[3]));
                    }
                } else {
                    addSummaryLineWarning("[RICH]: MSG_RICH_SIGNATURE_MISSING");
                }
                delete[] pRichData;
            }
        }
    }
}

void VBFile::parseResourceDirectory(PIMAGE_RESOURCE_DIRECTORY pResourceData, PBYTE pResourceBase, DWORD dwResourceDataSize) {
    if (!((PBYTE)pResourceData >= pResourceBase && (PBYTE)(pResourceData + 1) < pResourceBase + dwResourceDataSize))
        return;
    if (visited_resdirs.find(pResourceData) != visited_resdirs.end())
        return;
    visited_resdirs.insert(pResourceData);
    if (pResourceData->TimeDateStamp != 0) {
        resource_dir_timestamp.insert(pResourceData->TimeDateStamp);
    }
    if (options & VB_LEAK_RES_MAJOR) {
        MemoryDisclosure* leak = new MemoryDisclosure((PBYTE)pResourceData, sizeof(*pResourceData), pFileDataEnd, "ResourceDir Major");
        leak->maskSet(0, sizeof(*pResourceData), MemoryDisclosure::MASK_VALID);
        leak->maskSet(
                    offsetof(IMAGE_RESOURCE_DIRECTORY, MajorVersion),
                    sizeof(pResourceData->MajorVersion),
                    MemoryDisclosure::MASK_LEAK);
        addLeak(leak);
    }
    DWORD dwResourcesCount = pResourceData->NumberOfIdEntries + pResourceData->NumberOfNamedEntries;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceData + 1);
    for (DWORD i = 0; i < min(dwResourcesCount, MAX_RESOURCES_TO_PARSE); i++, pResourceEntry++) {
        if (!((PBYTE)pResourceEntry >= pResourceBase && (PBYTE)pResourceEntry < pResourceBase + dwResourceDataSize))
            return;
        if (pResourceEntry->DataIsDirectory) {
            PIMAGE_RESOURCE_DIRECTORY pNextDir = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)pResourceBase + pResourceEntry->OffsetToDirectory);
            parseResourceDirectory(pNextDir, pResourceBase, dwResourceDataSize);
        } else {
            if (pResourceEntry->NameIsString) {
                //
            } else {
                //
            }
        }
    }
}

void VBFile::readResources() {
    PIMAGE_RESOURCE_DIRECTORY pResourceData = NULL;
    DWORD dwResourceDataSize = pResourceDir->Size;
    pResourceData = (PIMAGE_RESOURCE_DIRECTORY)rvaToPointer(pResourceDir->VirtualAddress);
    if (isValidFilePointer(pResourceData, dwResourceDataSize) && dwResourceDataSize >= sizeof(*pResourceData)) {
        parseResourceDirectory(pResourceData, (PBYTE)pResourceData, dwResourceDataSize);
    }
}

void VBFile::readImport() {
    iVBVersion = -1;
    PIMAGE_IMPORT_DESCRIPTOR pImportData = (PIMAGE_IMPORT_DESCRIPTOR)rvaToPointer(pImportDir->VirtualAddress);
    DWORD dwImportDataSize = pImportDir->Size;
    if (isValidFilePointer(pImportData, dwImportDataSize) && dwImportDataSize >= sizeof(*pImportData)) {
        while (pImportData->Characteristics) {
            QString ImportDllName = safeReadString((PCHAR)rvaToPointer(pImportData->Name));
            if (ImportDllName.indexOf("msvbvm50", 0, Qt::CaseInsensitive) != -1)
                iVBVersion = 5;
            else if (ImportDllName.indexOf("msvbvm60", 0, Qt::CaseInsensitive) != -1)
                iVBVersion = 6;
            PIMAGE_THUNK_DATA32 pImportThunk = (PIMAGE_THUNK_DATA32)rvaToPointer(pImportData->OriginalFirstThunk);
            if (isValidFilePointer(pImportThunk, sizeof(*pImportThunk))) {
                while (pImportThunk->u1.AddressOfData) {
                    DWORD dwAPIaddress = pImportThunk->u1.AddressOfData;
                    if ((dwAPIaddress&0x80000000)==0x80000000) {
                        //
                    } else {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)rvaToPointer(dwAPIaddress);
                        if (isValidFilePointer(pImportByName, sizeof(*pImportByName))) {
                            QString APIName= safeReadString((PCHAR)pImportByName->Name);
                            if (options & VB_SUMMARY_PE_IMPORT)
                                addSummaryLine("[PE IMPORT]: " + ImportDllName + " " + APIName);
                        }
                    }
                    pImportThunk++;
                }
            }
            pImportData++;
        }
    }
}

void VBFile::detectProjData() {
    pProjData = (pVB_ProjInfo)vaToPointer(pVBHeader->lpProjectData);
    if (isValidFilePointer(pProjData, sizeof(*pProjData)))
        //if (pProjData->dwVersion == 500)
            return;
    pProjData = NULL;
}

void VBFile::detectEXEPROJDATA() {
    pVBHeader = NULL;
    PBYTE pEntryPoint = (PBYTE)rvaToPointer(EntryPoint);
    if (isValidFilePointer(pEntryPoint, 5 + 5) && pEntryPoint[0] == 0x68 && pEntryPoint[5] == 0xE8) {
        DWORD dwStructVa = *(DWORD*)(pEntryPoint + 1);
        pVBHeader = (PEXEPROJECTINFO)vaToPointer(dwStructVa);
        if (isValidFilePointer(pVBHeader, sizeof(*pVBHeader)) && memcmp(pVBHeader->szVbMagic, "VB", 2) == 0) {
            detectProjData();
        } else {
            pVBHeader = NULL;
        }
    }
    if (!pVBHeader && (options & VB_DETECT_BY_RAW_SEARCH)) {
        QSet<PVOID> m = findPattern((PBYTE)"VB5!", 4);
        for (auto match : m) {
            pVBHeader = (PEXEPROJECTINFO)match;
            detectProjData();
            if (pProjData)
                break;
        }
    }
}

VBFile::VBFile(QString filePath, qint64 options, QString charset) : options(options), charset(charset)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) throw Exception::EXCEPTION_FILE_NOT_OPEN;
    nFileSize = file.size();
    if (nFileSize < sizeof(IMAGE_DOS_HEADER)) throw Exception::EXCEPTION_FILE_NOT_PE;
    QByteArray dos_header = file.read(sizeof(IMAGE_DOS_HEADER));
    pDosHeader = (PIMAGE_DOS_HEADER)dos_header.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) throw Exception::EXCEPTION_FILE_NOT_PE;
    if (nFileSize > VB_MAX_FILE_SIZE) throw Exception::EXCEPTION_FILE_TOO_BIG;
    file.seek(0);
    fileBlob = file.readAll();
    file.close();
    bOptimizeLeaks = options & VB_OPTIMIZE_LEAKS;
    pFileData = (PBYTE)fileBlob.data();
    pFileDataEnd = pFileData + nFileSize;
    pDosHeader = (PIMAGE_DOS_HEADER)pFileData;
    pNtHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
    if (nFileSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) throw Exception::EXCEPTION_FILE_NOT_PE;
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) throw Exception::EXCEPTION_FILE_NOT_PE;
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) throw Exception::EXCEPTION_FILE_NOT_PE32;
    //
    pResourceDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    EntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    ImageBase = pNtHeaders->OptionalHeader.ImageBase;
    //
    readImport();
    if (iVBVersion == -1)
        throw Exception::EXCEPTION_FILE_NOT_VISUAL_BASIC_5_6;
    //
    if (options & VB_SUMMARY_RICH)
        readRichSignature();
    readResources();
    if (pNtHeaders->FileHeader.TimeDateStamp)
        addSummaryLine("[TIMESTAMP] FileHeader: " + QDateTime::fromTime_t(pNtHeaders->FileHeader.TimeDateStamp).toString());
    for (auto timestamp : resource_dir_timestamp) {
        addSummaryLine("[TIMESTAMP] Resource Directory: " + QDateTime::fromTime_t(timestamp).toString());
    }
    detectEXEPROJDATA();
    bIsUnparsable = !(pVBHeader && pProjData);
    if (!bIsUnparsable) {
        readVB56Structures();
    }
}

QString VBFile::getSummary() {
    return summary;
}

bool VBFile::isUnparsable() {
    return bIsUnparsable;
}

QVector<MemoryDisclosure*> & VBFile::getLeaks() {
    return leaks;
}

VBFile::~VBFile()
{

}
