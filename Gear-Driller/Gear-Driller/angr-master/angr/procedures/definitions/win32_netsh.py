# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("netsh.dll")
prototypes = \
    {
        #
        'MatchEnumTag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"pwszToken": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwValue": SimTypeInt(signed=False, label="UInt32")}, name="TOKEN_VALUE", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "pwcArg", "dwNumArg", "pEnumTable", "pdwValue"]),
        #
        'MatchToken': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUserToken", "pwszCmdToken"]),
        #
        'PreprocessCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"pwszTag": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwRequired": SimTypeInt(signed=False, label="UInt32"), "bPresent": SimTypeInt(signed=True, label="Int32")}, name="TAG_TYPE", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "ppwcArguments", "dwCurrentIndex", "dwArgCount", "pttTags", "dwTagCount", "dwMinArgs", "dwMaxArgs", "pdwTagType"]),
        #
        'PrintError': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "dwErrId"]),
        #
        'PrintMessageFromModule': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "dwMsgId"]),
        #
        'PrintMessage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszFormat"]),
        #
        'RegisterContext': SimTypeFunction([SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"dwVersion": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "_ullAlign": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), "pwszContext": SimTypePointer(SimTypeChar(label="Char"), offset=0), "guidHelper": SimTypeBottom(label="Guid"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "ulPriority": SimTypeInt(signed=False, label="UInt32"), "ulNumTopCmds": SimTypeInt(signed=False, label="UInt32"), "pTopCmds": SimTypePointer(SimStruct({"pwszCmdToken": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pfnCmdHandler": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszMachine", "ppwcArguments", "dwCurrentIndex", "dwArgCount", "dwFlags", "pvData", "pbDone"]), offset=0), "dwShortCmdHelpToken": SimTypeInt(signed=False, label="UInt32"), "dwCmdHlpToken": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pOsVersionCheck": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CIMOSType", "CIMOSProductSuite", "CIMOSVersion", "CIMOSBuildNumber", "CIMServicePackMajorVersion", "CIMServicePackMinorVersion", "uiReserved", "dwReserved"]), offset=0)}, name="CMD_ENTRY", pack=False, align=None), offset=0), "ulNumGroups": SimTypeInt(signed=False, label="UInt32"), "pCmdGroups": SimTypePointer(SimStruct({"pwszCmdGroupToken": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwShortCmdHelpToken": SimTypeInt(signed=False, label="UInt32"), "ulCmdGroupSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pCmdGroup": SimTypePointer(SimStruct({"pwszCmdToken": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pfnCmdHandler": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszMachine", "ppwcArguments", "dwCurrentIndex", "dwArgCount", "dwFlags", "pvData", "pbDone"]), offset=0), "dwShortCmdHelpToken": SimTypeInt(signed=False, label="UInt32"), "dwCmdHlpToken": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pOsVersionCheck": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CIMOSType", "CIMOSProductSuite", "CIMOSVersion", "CIMOSBuildNumber", "CIMServicePackMajorVersion", "CIMServicePackMinorVersion", "uiReserved", "dwReserved"]), offset=0)}, name="CMD_ENTRY", pack=False, align=None), offset=0), "pOsVersionCheck": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CIMOSType", "CIMOSProductSuite", "CIMOSVersion", "CIMOSBuildNumber", "CIMServicePackMajorVersion", "CIMServicePackMinorVersion", "uiReserved", "dwReserved"]), offset=0)}, name="CMD_GROUP_ENTRY", pack=False, align=None), offset=0), "pfnCommitFn": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwAction"]), offset=0), "pfnDumpFn": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszRouter", "ppwcArguments", "dwArgCount", "pvData"]), offset=0), "pfnConnectFn": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszMachine"]), offset=0), "pReserved": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "pfnOsVersionCheck": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CIMOSType", "CIMOSProductSuite", "CIMOSVersion", "CIMOSBuildNumber", "CIMServicePackMajorVersion", "CIMServicePackMinorVersion", "uiReserved", "dwReserved"]), offset=0)}, name="NS_CONTEXT_ATTRIBUTES", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pChildContext"]),
        #
        'RegisterHelper': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"dwVersion": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "_ullAlign": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), "guidHelper": SimTypeBottom(label="Guid"), "pfnStart": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pguidParent", "dwVersion"]), offset=0), "pfnStop": SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwReserved"]), offset=0)}, name="NS_HELPER_ATTRIBUTES", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pguidParentContext", "pfnRegisterSubContext"]),
    }

lib.set_prototypes(prototypes)
