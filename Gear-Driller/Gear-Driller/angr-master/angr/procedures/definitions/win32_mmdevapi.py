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
lib.set_library_names("mmdevapi.dll")
prototypes = \
    {
        #
        'ActivateAudioInterfaceAsync': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"vt": SimTypeShort(signed=False, label="UInt16"), "wReserved1": SimTypeShort(signed=False, label="UInt16"), "wReserved2": SimTypeShort(signed=False, label="UInt16"), "wReserved3": SimTypeShort(signed=False, label="UInt16"), "Anonymous": SimUnion({"cVal": SimTypeBottom(label="CHAR"), "bVal": SimTypeChar(label="Byte"), "iVal": SimTypeShort(signed=True, label="Int16"), "uiVal": SimTypeShort(signed=False, label="UInt16"), "lVal": SimTypeInt(signed=True, label="Int32"), "ulVal": SimTypeInt(signed=False, label="UInt32"), "intVal": SimTypeInt(signed=True, label="Int32"), "uintVal": SimTypeInt(signed=False, label="UInt32"), "hVal": SimTypeBottom(label="LARGE_INTEGER"), "uhVal": SimTypeBottom(label="ULARGE_INTEGER"), "fltVal": SimTypeFloat(size=32), "dblVal": SimTypeFloat(size=64), "boolVal": SimTypeShort(signed=True, label="Int16"), "__OBSOLETE__VARIANT_BOOL": SimTypeShort(signed=True, label="Int16"), "scode": SimTypeInt(signed=True, label="Int32"), "cyVal": SimTypeBottom(label="CY"), "date": SimTypeFloat(size=64), "filetime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "puuid": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "pclipdata": SimTypePointer(SimTypeBottom(label="CLIPDATA"), offset=0), "bstrVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "bstrblobVal": SimTypeBottom(label="BSTRBLOB"), "blob": SimTypeBottom(label="BLOB"), "pszVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pwszVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "punkVal": SimTypeBottom(label="IUnknown"), "pdispVal": SimTypeBottom(label="IDispatch"), "pStream": SimTypeBottom(label="IStream"), "pStorage": SimTypeBottom(label="IStorage"), "pVersionedStream": SimTypePointer(SimStruct({"guidVersion": SimTypeBottom(label="Guid"), "pStream": SimTypeBottom(label="IStream")}, name="VERSIONEDSTREAM", pack=False, align=None), offset=0), "parray": SimTypePointer(SimTypeBottom(label="SAFEARRAY"), offset=0), "cac": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CAC", pack=False, align=None), "caub": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CAUB", pack=False, align=None), "cai": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)}, name="CAI", pack=False, align=None), "caui": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)}, name="CAUI", pack=False, align=None), "cal": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)}, name="CAL", pack=False, align=None), "caul": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="CAUL", pack=False, align=None), "cah": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="LARGE_INTEGER"), offset=0)}, name="CAH", pack=False, align=None), "cauh": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="ULARGE_INTEGER"), offset=0)}, name="CAUH", pack=False, align=None), "caflt": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=32), offset=0)}, name="CAFLT", pack=False, align=None), "cadbl": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=64), offset=0)}, name="CADBL", pack=False, align=None), "cabool": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)}, name="CABOOL", pack=False, align=None), "cascode": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)}, name="CASCODE", pack=False, align=None), "cacy": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="CY"), offset=0)}, name="CACY", pack=False, align=None), "cadate": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=64), offset=0)}, name="CADATE", pack=False, align=None), "cafiletime": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0)}, name="CAFILETIME", pack=False, align=None), "cauuid": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="Guid"), offset=0)}, name="CACLSID", pack=False, align=None), "caclipdata": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="CLIPDATA"), offset=0)}, name="CACLIPDATA", pack=False, align=None), "cabstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="CABSTR", pack=False, align=None), "cabstrblob": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="BSTRBLOB"), offset=0)}, name="CABSTRBLOB", pack=False, align=None), "calpstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)}, name="CALPSTR", pack=False, align=None), "calpwstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="CALPWSTR", pack=False, align=None), "capropvar": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="PROPVARIANT"), offset=0)}, name="CAPROPVARIANT", pack=False, align=None), "pcVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pbVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "piVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "puiVal": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), "plVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pulVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pintVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "puintVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pfltVal": SimTypePointer(SimTypeFloat(size=32), offset=0), "pdblVal": SimTypePointer(SimTypeFloat(size=64), offset=0), "pboolVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "pdecVal": SimTypePointer(SimTypeBottom(label="DECIMAL"), offset=0), "pscode": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pcyVal": SimTypePointer(SimTypeBottom(label="CY"), offset=0), "pdate": SimTypePointer(SimTypeFloat(size=64), offset=0), "pbstrVal": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppunkVal": SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), "ppdispVal": SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0), "pparray": SimTypePointer(SimTypePointer(SimTypeBottom(label="SAFEARRAY"), offset=0), offset=0), "pvarVal": SimTypePointer(SimTypeBottom(label="PROPVARIANT"), offset=0)}, name="<anon>", label="None")}, name="_Anonymous_e__Struct", pack=False, align=None), "decVal": SimTypeBottom(label="DECIMAL")}, name="<anon>", label="None")}, name="PROPVARIANT", pack=False, align=None), offset=0), SimTypeBottom(label="IActivateAudioInterfaceCompletionHandler"), SimTypePointer(SimTypeBottom(label="IActivateAudioInterfaceAsyncOperation"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["deviceInterfacePath", "riid", "activationParams", "completionHandler", "activationOperation"]),
    }

lib.set_prototypes(prototypes)
