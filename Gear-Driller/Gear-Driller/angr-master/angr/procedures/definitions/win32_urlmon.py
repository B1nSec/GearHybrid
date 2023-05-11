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
lib.set_library_names("urlmon.dll")
prototypes = \
    {
        #
        'CreateURLMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "szURL", "ppmk"]),
        #
        'CreateURLMonikerEx': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "szURL", "ppmk", "dwFlags"]),
        #
        'GetClassURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szURL", "pClsID"]),
        #
        'CreateAsyncBindCtx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IEnumFORMATETC"), SimTypePointer(SimTypeBottom(label="IBindCtx"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "pBSCb", "pEFetc", "ppBC"]),
        #
        'CreateURLMonikerEx2': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IUri"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "pUri", "ppmk", "dwFlags"]),
        #
        'CreateAsyncBindCtxEx': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IEnumFORMATETC"), SimTypePointer(SimTypeBottom(label="IBindCtx"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "dwOptions", "pBSCb", "pEnum", "ppBC", "reserved"]),
        #
        'MkParseDisplayNameEx': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "szDisplayName", "pchEaten", "ppmk"]),
        #
        'RegisterBindStatusCallback': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypePointer(SimTypeBottom(label="IBindStatusCallback"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pBSCb", "ppBSCBPrev", "dwReserved"]),
        #
        'RevokeBindStatusCallback': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pBSCb"]),
        #
        'GetClassFileOrMime': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szFilename", "pBuffer", "cbSize", "szMime", "dwReserved", "pclsid"]),
        #
        'IsValidURL': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szURL", "dwReserved"]),
        #
        'CoGetClassObjectFromURL': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="CLSCTX"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rCLASSID", "szCODE", "dwFileVersionMS", "dwFileVersionLS", "szTYPE", "pBindCtx", "dwClsContext", "pvReserved", "riid", "ppv"]),
        #
        'IEInstallScope': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwScope"]),
        #
        'FaultInIEFeature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"tyspec": SimTypeInt(signed=False, label="UInt32"), "tagged_union": SimUnion({"clsid": SimTypeBottom(label="Guid"), "pFileExt": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pMimeType": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pProgId": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ByName": SimStruct({"pPackageName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "PolicyId": SimTypeBottom(label="Guid")}, name="_ByName_e__Struct", pack=False, align=None), "ByObjectId": SimStruct({"ObjectId": SimTypeBottom(label="Guid"), "PolicyId": SimTypeBottom(label="Guid")}, name="_ByObjectId_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="uCLSSPEC", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"dwContext": SimTypeInt(signed=False, label="UInt32"), "Platform": SimStruct({"dwPlatformId": SimTypeInt(signed=False, label="UInt32"), "dwVersionHi": SimTypeInt(signed=False, label="UInt32"), "dwVersionLo": SimTypeInt(signed=False, label="UInt32"), "dwProcessorArch": SimTypeInt(signed=False, label="UInt32")}, name="CSPLATFORM", pack=False, align=None), "Locale": SimTypeInt(signed=False, label="UInt32"), "dwVersionHi": SimTypeInt(signed=False, label="UInt32"), "dwVersionLo": SimTypeInt(signed=False, label="UInt32")}, name="QUERYCONTEXT", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pClassSpec", "pQuery", "dwFlags"]),
        #
        'GetComponentIDFromCLSSPEC': SimTypeFunction([SimTypePointer(SimStruct({"tyspec": SimTypeInt(signed=False, label="UInt32"), "tagged_union": SimUnion({"clsid": SimTypeBottom(label="Guid"), "pFileExt": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pMimeType": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pProgId": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ByName": SimStruct({"pPackageName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "PolicyId": SimTypeBottom(label="Guid")}, name="_ByName_e__Struct", pack=False, align=None), "ByObjectId": SimStruct({"ObjectId": SimTypeBottom(label="Guid"), "PolicyId": SimTypeBottom(label="Guid")}, name="_ByObjectId_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="uCLSSPEC", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pClassspec", "ppszComponentID"]),
        #
        'IsAsyncMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmk"]),
        #
        'RegisterMediaTypes': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ctypes", "rgszTypes", "rgcfTypes"]),
        #
        'FindMediaType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rgszTypes", "rgcfTypes"]),
        #
        'CreateFormatEnumerator': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"cfFormat": SimTypeShort(signed=False, label="UInt16"), "ptd": SimTypePointer(SimStruct({"tdSize": SimTypeInt(signed=False, label="UInt32"), "tdDriverNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdDeviceNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdPortNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdExtDevmodeOffset": SimTypeShort(signed=False, label="UInt16"), "tdData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DVTARGETDEVICE", pack=False, align=None), offset=0), "dwAspect": SimTypeInt(signed=False, label="UInt32"), "lindex": SimTypeInt(signed=True, label="Int32"), "tymed": SimTypeInt(signed=False, label="UInt32")}, name="FORMATETC", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IEnumFORMATETC"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cfmtetc", "rgfmtetc", "ppenumfmtetc"]),
        #
        'RegisterFormatEnumerator': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IEnumFORMATETC"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pEFetc", "reserved"]),
        #
        'RevokeFormatEnumerator': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IEnumFORMATETC")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pEFetc"]),
        #
        'RegisterMediaTypeClass': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "ctypes", "rgszTypes", "rgclsID", "reserved"]),
        #
        'FindMediaTypeClass': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szType", "pclsID", "reserved"]),
        #
        'UrlMkSetSessionOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pBuffer", "dwBufferLength", "dwReserved"]),
        #
        'UrlMkGetSessionOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pBuffer", "dwBufferLength", "pdwBufferLengthOut", "dwReserved"]),
        #
        'FindMimeFromData': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pwzUrl", "pBuffer", "cbSize", "pwzMimeProposed", "dwMimeFlags", "ppwzMimeOut", "dwReserved"]),
        #
        'ObtainUserAgentString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pszUAOut", "cbSize"]),
        #
        'CompareSecurityIds': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbSecurityId1", "dwLen1", "pbSecurityId2", "dwLen2", "dwReserved"]),
        #
        'CompatFlagsFromClsid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pclsid", "pdwCompatFlags", "pdwMiscStatusFlags"]),
        #
        'SetAccessForIEAppContainer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IEObjectType"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "ieObjectType", "dwAccessMask"]),
        #
        'CreateUri': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="URI_CREATE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzURI", "dwFlags", "dwReserved", "ppURI"]),
        #
        'CreateUriWithFragment': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzURI", "pwzFragment", "dwFlags", "dwReserved", "ppURI"]),
        #
        'CreateUriFromMultiByteString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszANSIInputUri", "dwEncodingFlags", "dwCodePage", "dwCreateFlags", "dwReserved", "ppUri"]),
        #
        'CreateIUriBuilder': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUriBuilder"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIUri", "dwFlags", "dwReserved", "ppIUriBuilder"]),
        #
        'HlinkSimpleNavigateToString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szTarget", "szLocation", "szTargetFrameName", "pUnk", "pbc", "param5", "grfHLNF", "dwReserved"]),
        #
        'HlinkSimpleNavigateToMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkTarget", "szLocation", "szTargetFrameName", "pUnk", "pbc", "param5", "grfHLNF", "dwReserved"]),
        #
        'URLOpenStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenPullStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenPullStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLDownloadToFileA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLDownloadToFileW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLDownloadToCacheFileA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "cchFileName", "param4", "param5"]),
        #
        'URLDownloadToCacheFileW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "cchFileName", "param4", "param5"]),
        #
        'URLOpenBlockingStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLOpenBlockingStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'HlinkGoBack': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'HlinkGoForward': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'HlinkNavigateString': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "szTarget"]),
        #
        'HlinkNavigateMoniker': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "pmkTarget"]),
        #
        'CoInternetParseUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PARSEACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "ParseAction", "dwFlags", "pszResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetParseIUri': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="PARSEACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIUri", "ParseAction", "dwFlags", "pwzResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetCombineUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzBaseUrl", "pwzRelativeUrl", "dwCombineFlags", "pszResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetCombineUrlEx': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBaseUri", "pwzRelativeUrl", "dwCombineFlags", "ppCombinedUri", "dwReserved"]),
        #
        'CoInternetCombineIUri': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBaseUri", "pRelativeUri", "dwCombineFlags", "ppCombinedUri", "dwReserved"]),
        #
        'CoInternetCompareUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl1", "pwzUrl2", "dwFlags"]),
        #
        'CoInternetGetProtocolFlags': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "pdwFlags", "dwReserved"]),
        #
        'CoInternetQueryInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="QUERYOPTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "QueryOptions", "dwQueryFlags", "pvBuffer", "cbBuffer", "pcbBuffer", "dwReserved"]),
        #
        'CoInternetGetSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IInternetSession"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwSessionMode", "ppIInternetSession", "dwReserved"]),
        #
        'CoInternetGetSecurityUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="PSUACTION"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUrl", "ppwszSecUrl", "psuAction", "dwReserved"]),
        #
        'CoInternetGetSecurityUrlEx': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypeInt(signed=False, label="PSUACTION"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUri", "ppSecUri", "psuAction", "dwReserved"]),
        #
        'CoInternetSetFeatureEnabled': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "fEnable"]),
        #
        'CoInternetIsFeatureEnabled': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags"]),
        #
        'CoInternetIsFeatureEnabledForUrl': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IInternetSecurityManager")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "szURL", "pSecMgr"]),
        #
        'CoInternetIsFeatureEnabledForIUri': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUri"), SimTypeBottom(label="IInternetSecurityManagerEx2")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "pIUri", "pSecMgr"]),
        #
        'CoInternetIsFeatureZoneElevationEnabled': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IInternetSecurityManager"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFromURL", "szToURL", "pSecMgr", "dwFlags"]),
        #
        'CopyStgMedium': SimTypeFunction([SimTypePointer(SimStruct({"tymed": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"hBitmap": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hMetaFilePict": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "hEnhMetaFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hGlobal": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pstm": SimTypeBottom(label="IStream"), "pstg": SimTypeBottom(label="IStorage")}, name="<anon>", label="None"), "pUnkForRelease": SimTypeBottom(label="IUnknown")}, name="STGMEDIUM", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"tymed": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"hBitmap": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hMetaFilePict": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "hEnhMetaFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hGlobal": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pstm": SimTypeBottom(label="IStream"), "pstg": SimTypeBottom(label="IStorage")}, name="<anon>", label="None"), "pUnkForRelease": SimTypeBottom(label="IUnknown")}, name="STGMEDIUM", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcstgmedSrc", "pstgmedDest"]),
        #
        'CopyBindInfo': SimTypeFunction([SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "szExtraInfo": SimTypePointer(SimTypeChar(label="Char"), offset=0), "stgmedData": SimStruct({"tymed": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"hBitmap": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hMetaFilePict": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "hEnhMetaFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hGlobal": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pstm": SimTypeBottom(label="IStream"), "pstg": SimTypeBottom(label="IStorage")}, name="<anon>", label="None"), "pUnkForRelease": SimTypeBottom(label="IUnknown")}, name="STGMEDIUM", pack=False, align=None), "grfBindInfoF": SimTypeInt(signed=False, label="UInt32"), "dwBindVerb": SimTypeInt(signed=False, label="UInt32"), "szCustomVerb": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cbstgmedData": SimTypeInt(signed=False, label="UInt32"), "dwOptions": SimTypeInt(signed=False, label="UInt32"), "dwOptionsFlags": SimTypeInt(signed=False, label="UInt32"), "dwCodePage": SimTypeInt(signed=False, label="UInt32"), "securityAttributes": SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), "iid": SimTypeBottom(label="Guid"), "pUnk": SimTypeBottom(label="IUnknown"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="BINDINFO", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "szExtraInfo": SimTypePointer(SimTypeChar(label="Char"), offset=0), "stgmedData": SimStruct({"tymed": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"hBitmap": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hMetaFilePict": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "hEnhMetaFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hGlobal": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pstm": SimTypeBottom(label="IStream"), "pstg": SimTypeBottom(label="IStorage")}, name="<anon>", label="None"), "pUnkForRelease": SimTypeBottom(label="IUnknown")}, name="STGMEDIUM", pack=False, align=None), "grfBindInfoF": SimTypeInt(signed=False, label="UInt32"), "dwBindVerb": SimTypeInt(signed=False, label="UInt32"), "szCustomVerb": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cbstgmedData": SimTypeInt(signed=False, label="UInt32"), "dwOptions": SimTypeInt(signed=False, label="UInt32"), "dwOptionsFlags": SimTypeInt(signed=False, label="UInt32"), "dwCodePage": SimTypeInt(signed=False, label="UInt32"), "securityAttributes": SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), "iid": SimTypeBottom(label="Guid"), "pUnk": SimTypeBottom(label="IUnknown"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="BINDINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcbiSrc", "pbiDest"]),
        #
        'ReleaseBindInfo': SimTypeFunction([SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "szExtraInfo": SimTypePointer(SimTypeChar(label="Char"), offset=0), "stgmedData": SimStruct({"tymed": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"hBitmap": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hMetaFilePict": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "hEnhMetaFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hGlobal": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pstm": SimTypeBottom(label="IStream"), "pstg": SimTypeBottom(label="IStorage")}, name="<anon>", label="None"), "pUnkForRelease": SimTypeBottom(label="IUnknown")}, name="STGMEDIUM", pack=False, align=None), "grfBindInfoF": SimTypeInt(signed=False, label="UInt32"), "dwBindVerb": SimTypeInt(signed=False, label="UInt32"), "szCustomVerb": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cbstgmedData": SimTypeInt(signed=False, label="UInt32"), "dwOptions": SimTypeInt(signed=False, label="UInt32"), "dwOptionsFlags": SimTypeInt(signed=False, label="UInt32"), "dwCodePage": SimTypeInt(signed=False, label="UInt32"), "securityAttributes": SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), "iid": SimTypeBottom(label="Guid"), "pUnk": SimTypeBottom(label="IUnknown"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="BINDINFO", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pbindinfo"]),
        #
        'IEGetUserPrivateNamespaceName': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Char"), offset=0)),
        #
        'CoInternetCreateSecurityManager': SimTypeFunction([SimTypeBottom(label="IServiceProvider"), SimTypePointer(SimTypeBottom(label="IInternetSecurityManager"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSP", "ppSM", "dwReserved"]),
        #
        'CoInternetCreateZoneManager': SimTypeFunction([SimTypeBottom(label="IServiceProvider"), SimTypePointer(SimTypeBottom(label="IInternetZoneManager"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSP", "ppZM", "dwReserved"]),
        #
        'GetSoftwareUpdateInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwAdState": SimTypeInt(signed=False, label="UInt32"), "szTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "szAbstract": SimTypePointer(SimTypeChar(label="Char"), offset=0), "szHREF": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwInstalledVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwInstalledVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwUpdateVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwUpdateVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwAdvertisedVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwAdvertisedVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="SOFTDISTINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szDistUnit", "psdi"]),
        #
        'SetSoftwareUpdateAdvertisementState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szDistUnit", "dwAdState", "dwAdvertisedVersionMS", "dwAdvertisedVersionLS"]),
        #
        'IsLoggingEnabledA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl"]),
        #
        'IsLoggingEnabledW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUrl"]),
        #
        'WriteHitLogging': SimTypeFunction([SimTypePointer(SimStruct({"dwStructSize": SimTypeInt(signed=False, label="UInt32"), "lpszLoggedUrlName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "StartTime": SimStruct({"wYear": SimTypeShort(signed=False, label="UInt16"), "wMonth": SimTypeShort(signed=False, label="UInt16"), "wDayOfWeek": SimTypeShort(signed=False, label="UInt16"), "wDay": SimTypeShort(signed=False, label="UInt16"), "wHour": SimTypeShort(signed=False, label="UInt16"), "wMinute": SimTypeShort(signed=False, label="UInt16"), "wSecond": SimTypeShort(signed=False, label="UInt16"), "wMilliseconds": SimTypeShort(signed=False, label="UInt16")}, name="SYSTEMTIME", pack=False, align=None), "EndTime": SimStruct({"wYear": SimTypeShort(signed=False, label="UInt16"), "wMonth": SimTypeShort(signed=False, label="UInt16"), "wDayOfWeek": SimTypeShort(signed=False, label="UInt16"), "wDay": SimTypeShort(signed=False, label="UInt16"), "wHour": SimTypeShort(signed=False, label="UInt16"), "wMinute": SimTypeShort(signed=False, label="UInt16"), "wSecond": SimTypeShort(signed=False, label="UInt16"), "wMilliseconds": SimTypeShort(signed=False, label="UInt16")}, name="SYSTEMTIME", pack=False, align=None), "lpszExtendedInfo": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="HIT_LOGGING_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLogginginfo"]),
    }

lib.set_prototypes(prototypes)