#ifndef VB5_6_H
#define VB5_6_H

#include "common.h"

#pragma pack(push, 1)

typedef struct {
    CHAR szVbMagic[4]; // “VB5!” String
    WORD wRuntimeBuild; // Build of the VB6 Runtime
    CHAR szLangDll[14]; // Language Extension DLL
    CHAR szSecLangDll[14]; // 2nd Language Extension DLL
    WORD wRuntimeRevision; // Internal Runtime Revision
    DWORD dwLCID; // LCID of Language DLL
    DWORD dwSecLCID; // LCID of 2nd Language DLL
    DWORD lpSubMain; // Pointer to Sub Main Code
    DWORD lpProjectData; // Pointer to Project Data
    DWORD fMdlIntCtls; // VB Control Flags for IDs < 32
    DWORD fMdlIntCtls2; // VB Control Flags for IDs > 32
    DWORD dwThreadFlags; // Threading Mode
    DWORD dwThreadCount; // Threads to support in pool
    WORD wFormCount; // Number of forms present
    WORD wExternalComponentCount; // Number of external controls
    DWORD dwThunkCount; // Number of thunks to create
    DWORD lpGuiTable; // Pointer to GUI Table
    DWORD lpExternalComponentTable; // Pointer to External Table
    DWORD lpComRegisterData; // Pointer to COM Information
    DWORD bSZProjectDescription; // Offset to Project Description
    DWORD bSZProjectExeName; // Offset to Project EXE Name
    DWORD bSZProjectHelpFile; // Offset to Project Help File
    DWORD bSZProjectName; // Offset to Project Name
} EXEPROJECTINFO, *PEXEPROJECTINFO;

typedef struct {
    DWORD dwVersion; // 5.00 in Hex (0x1F4). Version.
    DWORD lpObjectTable; // Pointer to the Object Table
    DWORD dwNull; // Unused value after compilation.
    DWORD lpCodeStart; // Points to start of code. Unused.
    DWORD lpCodeEnd; // Points to end of code. Unused.
    DWORD dwDataSize; // Size of VB Object Structures. Unused.
    DWORD lpThreadSpace; // Pointer to Pointer to Thread Object.
    DWORD lpVbaSeh; // Pointer to VBA Exception Handler
    DWORD lpNativeCode; // Pointer to .DATA section.
    WCHAR wsPrimitivePath[3]; // ID string.
    WCHAR wsProjectPath[261]; // Contains Path. Empty for < SP6
    DWORD lpExternalTable; // Pointer to External Table.
    DWORD dwExternalCount; // Objects in the External Table.
} VB_ProjInfo, *pVB_ProjInfo;

typedef struct {
    DWORD bRegInfo; // Offset to COM Interfaces Info
    DWORD bSZProjectName; // Offset to Project/Typelib Name
    DWORD bSZHelpDirectory; // Offset to Help Directory
    DWORD bSZProjectDescription; // Offset to Project Description
    UUID uuidProjectClsId; // CLSID of Project/Typelib
    DWORD dwTlbLcid; // LCID of Type Library
    WORD wUnknown; // Might be something. Must check
    WORD wTlbVerMajor; // Typelib Major Version
    WORD wTlbVerMinor; // Typelib Minor Version
} VB_ComRegData, *pVB_ComRegData;

typedef struct {
    DWORD bNextObject; // Offset to COM Interfaces Info
    DWORD bObjectName; // Offset to Object Name
    DWORD bObjectDescription; // Offset to Object Description
    DWORD dwInstancing; // Instancing Mode
    DWORD dwObjectId; // Current Object ID in the Project
    UUID uuidObject; // CLSID of Object
    DWORD fIsInterface; // Specifies if the next CLSID is valid
    DWORD bUuidObjectIFace; // Offset to CLSID of Object Interface
    DWORD bUuidEventsIFace; // Offset to CLSID of Events Interface
    DWORD fHasEvents; // Specifies if the CLSID above is valid
    DWORD dwMiscStatus; // OLEMISC Flags (see MSDN docs)
    BYTE fClassType; // Class Type
    BYTE fObjectType; // Flag identifying the Object Type
    WORD wToolboxBitmap32; // Control Bitmap ID in Toolbox
    WORD wDefaultIcon; // Minimized Icon of Control Window
    WORD fIsDesigner; // Specifies whether this is a Designer
    DWORD bDesignerData; // Offset to Designer Data
} VB_ComRegInfo, *pVB_ComRegInfo;

typedef struct {
    DWORD lpHeapLink; // Unused after compilation, always 0.
    DWORD lpObjectTable; // Back-Pointer to the Object Table.
    DWORD dwReserved; // Always set to -1 after compiling. Unused
    DWORD dwUnused; // Not written or read in any case.
    DWORD lpObjectList; // Pointer to Object Descriptor Pointers.
    DWORD dwUnused2; // Not written or read in any case.
    DWORD szProjectDescription; // Pointer to Project Description
    DWORD szProjectHelpFile; // Pointer to Project Help File
    DWORD dwReserved2; // Always set to -1 after compiling. Unused
    DWORD dwHelpContextId; // Help Context ID set in Project Settings.
} VB_SecondaryProjInfo, *pVB_SecondaryProjInfo;

/* Semi Decompiler (c)
    VB_PublicObjectDescr.fObjectType Properties
    #########################################################
    form:              0000 0001 1000 0000 1000 0011 --> 18083
                       0000 0001 1000 0000 1010 0011 --> 180A3
                       0000 0001 1000 0000 1100 0011 --> 180C3
    module:            0000 0001 1000 0000 0000 0001 --> 18001
                       0000 0001 1000 0000 0010 0001 --> 18021
    class:             0001 0001 1000 0000 0000 0011 --> 118003
                       0001 0011 1000 0000 0000 0011 --> 138003
                       0000 0001 1000 0000 0010 0011 --> 18023
                       0000 0001 1000 1000 0000 0011 --> 18803
                       0001 0001 1000 1000 0000 0011 --> 118803
    usercontrol:       0001 1101 1010 0000 0000 0011 --> 1DA003
                       0001 1101 1010 0000 0010 0011 --> 1DA023
                       0001 1101 1010 1000 0000 0011 --> 1DA803
    propertypage:      0001 0101 1000 0000 0000 0011 --> 158003
                          | ||     |  |    | |    |
    [moog]                | ||     |  |    | |    |
    HasPublicInterface ---+ ||     |  |    | |    |
    HasPublicEvents --------+|     |  |    | |    |
    IsCreatable/Visible? ----+     |  |    | |    |
    Same as "HasPublicEvents" -----+  |    | |    |
    [aLfa]                         |  |    | |    |
    usercontrol (1) ---------------+  |    | |    |
    ocx/dll (1) ----------------------+    | |    |
    form (1) ------------------------------+ |    |
    vb5 (1) ---------------------------------+    |
    HasOptInfo (1) -------------------------------+
                                                  |
    module(0) ------------------------------------+
*/

typedef struct {
    DWORD lpObjectInfo; // Pointer to the Object Info for this Object.
    DWORD dwReserved; // Always set to -1 after compiling.
    DWORD lpPublicBytes; // Pointer to Public Variable Size integers.
    DWORD lpStaticBytes; // Pointer to Static Variable Size integers.
    DWORD lpModulePublic; // Pointer to Public Variables in DATA section
    DWORD lpModuleStatic; // Pointer to Static Variables in DATA section
    DWORD lpszObjectName; // Name of the Object.
    DWORD dwMethodCount; // Number of Methods in Object.
    DWORD lpMethodNames; // If present, pointer to Method names array.
    DWORD bStaticVars; // Offset to where to copy Static Variables.
    DWORD fObjectType; // Flags defining the Object Type.
    DWORD dwNull; // Not valid after compilation.
} VB_PublicObjectDescr, *pVB_PublicObjectDescr;

typedef struct {
    DWORD lpHeapLink; // Unused after compilation, always 0.
    DWORD lpExecProj; // Pointer to VB Project Exec COM Object.
    DWORD lpProjectInfo2; // Secondary Project Information.
    DWORD dwReserved; // Always set to - 1 after compiling.Unused
    DWORD dwNull; // Not used in compiled mode.
    DWORD lpProjectObject; // Pointer to in - memory Project Data.
    UUID uuidObject; // GUID of the Object Table.
    WORD fCompileState; // Internal flag used during compilation.
    WORD dwTotalObjects; // Total objects present in Project.
    WORD dwCompiledObjects; // Equal to above after compiling.
    WORD dwObjectsInUse; // Usually equal to above after compile.
    DWORD lpObjectArray; // Pointer to Object Descriptors
    DWORD fIdeFlag; // Flag / Pointer used in IDE only.
    DWORD lpIdeData; // Flag / Pointer used in IDE only.
    DWORD lpIdeData2; // Flag / Pointer used in IDE only.
    DWORD lpszProjectName; // Pointer to Project Name.
    DWORD dwLcid; // LCID of Project.
    DWORD dwLcid2; // Alternate LCID of Project.
    DWORD lpIdeData3; // Flag / Pointer used in IDE only.
    DWORD dwIdentifier; // Template Version of Structure.
} VB_ObjectTable, *pVB_ObjectTable;

typedef struct {
    WORD wRefCount; // Always 1 after compilation.
    WORD wObjectIndex; // Index of this Object.
    DWORD lpObjectTable; // Pointer to the Object Table
    DWORD lpIdeData; // Zero after compilation. Used in IDE only.
    DWORD lpPrivateObject; // Pointer to Private Object Descriptor.
    DWORD dwReserved; // Always -1 after compilation.
    DWORD dwNull; // Unused.
    DWORD lpObject; // Back-Pointer to Public Object Descriptor.
    DWORD lpProjectData; // Pointer to in-memory Project Object.
    WORD wMethodCount; // Number of Methods
    WORD wMethodCountUsed; // Zeroed out after compilation. IDE only.
    DWORD lpMethods; // Pointer to Array of Methods.
    WORD wConstants; // Number of Constants in Constant Pool.
    WORD wMaxConstants; // Constants to allocate in Constant Pool.
    DWORD lpIdeData2; // Valid in IDE only.
    DWORD lpIdeData3; // Valid in IDE only.
    DWORD lpConstants; // Pointer to Constants Pool.
} VB_ObjectInfo, *pVB_ObjectInfo;

typedef struct {
    DWORD dwObjectGuids; // How many GUIDs to Register. 2 = Designer
    DWORD lpObjectGuid; // Unique GUID of the Object *VERIFY*
    DWORD dwNull; // Unused.
    DWORD lpuuidObjectTypes; // Pointer to Array of Object Interface GUIDs
    DWORD dwObjectTypeGuids; // How many GUIDs in the Array above.
    DWORD lpControls2; // Usually the same as lpControls.
    DWORD dwNull2; // Unused.
    DWORD lpObjectGuid2; // Pointer to Array of Object GUIDs.
    DWORD dwControlCount; // Number of Controls in array below.
    DWORD lpControls; // Pointer to Controls Array.
    WORD wEventCount; // Number of Events in Event Array.
    WORD wPCodeCount; // Number of P-Codes used by this Object.
    WORD bWInitializeEvent; // Offset to Initialize Event from Event Table.
    WORD bWTerminateEvent; // Offset to Terminate Event in Event Table.
    DWORD lpEvents; // Pointer to Events Array.
    DWORD lpBasicClassObject; // Pointer to in-memory Class Objects.
    DWORD dwNull3; // Unused.
    DWORD lpIdeData; // Only valid in IDE.
} VB_OptionalObjectInfo, *pVB_OptionalObjectInfo;

typedef struct {
    DWORD fControlType; // Type of control.
    WORD wEventcount; // Number of Event Handlers supported.
    WORD bWEventsOffset; // Offset in to Memory struct to copy Events.
    DWORD lpGuid; // Pointer to GUID of this Control.
    DWORD dwIndex; // Index ID of this Control.
    DWORD dwNull; // Unused.
    DWORD dwNull2; // Unused.
    DWORD lpEventTable; // Pointer to Event Handler Table.
    DWORD lpIdeData; // Valid in IDE only.
    DWORD lpszName; // Name of this Control.
    DWORD dwIndexCopy; // Secondary Index ID of this Control.
} VB_ControlInfo, *pVB_ControlInfo;

typedef unsigned short RESDESCFLAGS;

typedef struct {
    WORD wUnkOffset;
    RESDESCFLAGS wTypeFlags;
    union {
        struct {
            WORD wUnused1; // leak
            WORD wUnused2; // leak
            RESDESCFLAGS wType2;
            WORD wUnused3; // leak
            WORD wUnused4; // leak
            WORD wUnused5; // leak
            BYTE SaBase1[16]; // SAFEARRAY
            BYTE SaBase2[16]; // SAFEARRAY
        } Type5;
        struct {
            WORD wLength; // string length
        } Type4;
        struct {
            WORD wUnused1; // leak
            WORD wUnknown; // usually 0xffff
            DWORD lpSubResDscrTbl;
            WORD wUnused2; // leak
            WORD wUnused3; // leak
            WORD wUnused4; // leak
            WORD wUnused5; // leak
            WORD wUnused6; // leak
            WORD wUnused7; // leak
            WORD wUnused8; // leak
            WORD wUnused9; // leak
        } Type9;
    } var;
} RESDESC;

typedef struct {
    WORD wTotalBytes;
    WORD wFlags1;
    WORD wCount1;
    WORD wCount2;
    WORD wFlags2;
    WORD wFlags3;
    RESDESC resdesc;
} RESDESCTBL;

typedef struct {
    DWORD dwType;
    DWORD lpValue;
} VB_ExternTable, *pVB_ExternTable;

typedef struct {
    DWORD lpszLibraryName;
    DWORD lpszImportFunction;
    DWORD lpUnknown;
    DWORD dwNull1;
    DWORD dwNull2;
} VB_ApiImportType7, *pVB_ApiImportType7;

typedef struct {
    DWORD lpUuid;
    DWORD lpUnknown;
} VB_ApiImportType6, *pVB_ApiImportType6;

// vba6.exe : _WriteFormExeData
// Semi: tGuiTable
typedef struct {
    DWORD dwStructSize; // Total size of this structure
    UUID uuidObjectGUI; // UUID of Object GUI
    DWORD dwUnknown1;
    DWORD dwUnknown2;
    DWORD dwUnknown3;
    DWORD dwUnknown4;
    DWORD lObjectID; // Current Object ID in the Project
    DWORD dwUnknown5;
    DWORD fOLEMisc; // OLEMisc Flags
    UUID uuidObject; // UUID of Object
    DWORD dwSizeOfFormBody; // Pointer to GUI Object Info
    DWORD dwUnknown7;
    DWORD lpFormBody;
} EXEFORMINFO, PEXEFORMINFO;

// msvbvm60 ProjOpenRT->LoadExeResources->_CreateOcxDefFromExe
typedef struct {
    DWORD dwStructSize;
    DWORD dwUuid;
    DWORD dwBlobOffset;
    DWORD dwUnknownOffset1;
    DWORD dwUnknownOffset2; // sizeof = 8
    DWORD dwUnknownOffset3; // sizeof = 8
    DWORD dwUnknownOffset4;
    DWORD dwGUIDoffset;
    DWORD dwGUIDlength;
    DWORD dwUnknownOffset5;
    DWORD dwFileNameOffset;
    DWORD dwSourceOffset;
    DWORD dwNameOffset;
	DWORD unknown;
} EXEOCXINFO, PEXEOCXINFO;

typedef struct {
    DWORD lpInfo;
    DWORD lpUuid;
    DWORD lpUnknown;
} VB_OLB_Header, *pVB_OLB_Header;

typedef struct {
    DWORD lpUnknown1;
    DWORD dwUnknown1;
    DWORD dwUnknown2;
    DWORD dwUnknown3;
    DWORD pszPath;
    DWORD pszName;
    DWORD lpUnknown2;
} VB_OLB_Info, *pVB_OLB_Info;

typedef struct {
    DWORD lpObjectInfo;
    WORD wFlag1;
    WORD wFlag2;
    WORD wCodeLength;
    DWORD wFlag3;
    WORD wFlag4;
    WORD wNull;
    DWORD wFlag5;
    WORD wFlag6;
} VB_Method, *pVB_Method;

typedef struct {
    DWORD len;
    CHAR str[1];
} BSTR, *PBSTR;

#define BSTR_SKIP(X) (&X->str + X->len)

typedef struct {
    UUID  uuidDesigner; // CLSID of the Addin/Designer
    DWORD cbStructSize; // Total Size of the next fields.
    BYTE base;
} VB_ComDesigner, *pVB_ComDesigner;

/*
 * 0x0  UUID  uuidDesigner           CLSID of the Addin/Designer
 * 0x10 DWORD cbStructSize           Total Size of the next fields.
 * 0x14 BSTR  bstrAddinRegKey        Registry Key of the Addin
 * VAR  BSTR  bstrAddinName          Friendly Name of the Addin
 * VAR  BSTR  bstrAddinDescription   Description of Addin
 * VAR  BSTR  dwLoadBehaviour        CLSID of Object
 * VAR  BSTR  bstrSatelliteDll       Satellite DLL, if specified
 * VAR  BSTR  bstrAdditionalRegKey   Extra Registry Key, if specified
 * VAR  DWORD dwCommandLineSafe      Specifies a GUI-less Addin if 1.
 */

#pragma pack(pop)

// Functions

BOOL RESDESCFLAGS__HasResource(RESDESCFLAGS pflags);
tagSAFEARRAY * RESDESC__Psa(RESDESC *presdesc);
size_t RESDESC__CbSize(RESDESC *presdesc);

#endif // VB5_6_H
