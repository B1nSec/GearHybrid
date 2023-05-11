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
lib.set_library_names("scarddlg.dll")
prototypes = \
    {
        #
        'SCardUIDlgSelectCardA': SimTypeFunction([SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "hSCardContext": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "lpstrTitle": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpstrSearchDesc": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hIcon": SimTypeBottom(label="HICON"), "pOpenCardSearchCriteria": SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "lpstrGroupNames": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxGroupNames": SimTypeInt(signed=False, label="UInt32"), "rgguidInterfaces": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "cguidInterfaces": SimTypeInt(signed=False, label="UInt32"), "lpstrCardNames": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxCardNames": SimTypeInt(signed=False, label="UInt32"), "lpfnCheck": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lpfnDisconnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2"]), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32")}, name="OPENCARD_SEARCH_CRITERIAA", pack=False, align=None), offset=0), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32"), "lpstrRdr": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxRdr": SimTypeInt(signed=False, label="UInt32"), "lpstrCard": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxCard": SimTypeInt(signed=False, label="UInt32"), "dwActiveProtocol": SimTypeInt(signed=False, label="UInt32"), "hCardHandle": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="OPENCARDNAME_EXA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'SCardUIDlgSelectCardW': SimTypeFunction([SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "hSCardContext": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "lpstrTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpstrSearchDesc": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hIcon": SimTypeBottom(label="HICON"), "pOpenCardSearchCriteria": SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "lpstrGroupNames": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxGroupNames": SimTypeInt(signed=False, label="UInt32"), "rgguidInterfaces": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "cguidInterfaces": SimTypeInt(signed=False, label="UInt32"), "lpstrCardNames": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxCardNames": SimTypeInt(signed=False, label="UInt32"), "lpfnCheck": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lpfnDisconnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2"]), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32")}, name="OPENCARD_SEARCH_CRITERIAW", pack=False, align=None), offset=0), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32"), "lpstrRdr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxRdr": SimTypeInt(signed=False, label="UInt32"), "lpstrCard": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxCard": SimTypeInt(signed=False, label="UInt32"), "dwActiveProtocol": SimTypeInt(signed=False, label="UInt32"), "hCardHandle": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="OPENCARDNAME_EXW", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetOpenCardNameA': SimTypeFunction([SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hSCardContext": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "lpstrGroupNames": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxGroupNames": SimTypeInt(signed=False, label="UInt32"), "lpstrCardNames": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxCardNames": SimTypeInt(signed=False, label="UInt32"), "rgguidInterfaces": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "cguidInterfaces": SimTypeInt(signed=False, label="UInt32"), "lpstrRdr": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxRdr": SimTypeInt(signed=False, label="UInt32"), "lpstrCard": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nMaxCard": SimTypeInt(signed=False, label="UInt32"), "lpstrTitle": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32"), "dwActiveProtocol": SimTypeInt(signed=False, label="UInt32"), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lpfnCheck": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), "lpfnDisconnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2"]), offset=0), "hCardHandle": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="OPENCARDNAMEA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetOpenCardNameW': SimTypeFunction([SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hSCardContext": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "lpstrGroupNames": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxGroupNames": SimTypeInt(signed=False, label="UInt32"), "lpstrCardNames": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxCardNames": SimTypeInt(signed=False, label="UInt32"), "rgguidInterfaces": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "cguidInterfaces": SimTypeInt(signed=False, label="UInt32"), "lpstrRdr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxRdr": SimTypeInt(signed=False, label="UInt32"), "lpstrCard": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nMaxCard": SimTypeInt(signed=False, label="UInt32"), "lpstrTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwShareMode": SimTypeInt(signed=False, label="UInt32"), "dwPreferredProtocols": SimTypeInt(signed=False, label="UInt32"), "dwActiveProtocol": SimTypeInt(signed=False, label="UInt32"), "lpfnConnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lpfnCheck": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), "lpfnDisconnect": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2"]), offset=0), "hCardHandle": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="OPENCARDNAMEW", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'SCardDlgExtendedError': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)