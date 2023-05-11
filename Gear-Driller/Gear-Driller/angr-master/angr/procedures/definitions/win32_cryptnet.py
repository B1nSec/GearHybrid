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
lib.set_library_names("cryptnet.dll")
prototypes = \
    {
        #
        'CryptRetrieveObjectByUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pszCredentialsOid": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pvCredentials": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="CRYPT_CREDENTIALS", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pLastSyncTime": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), "dwMaxUrlRetrievalByteCount": SimTypeInt(signed=False, label="UInt32"), "pPreFetchInfo": SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwObjectType": SimTypeInt(signed=False, label="UInt32"), "dwError": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32"), "ThisUpdateTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "NextUpdateTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "PublishTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None)}, name="CRYPTNET_URL_CACHE_PRE_FETCH_INFO", pack=False, align=None), offset=0), "pFlushInfo": SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwExemptSeconds": SimTypeInt(signed=False, label="UInt32"), "ExpireTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None)}, name="CRYPTNET_URL_CACHE_FLUSH_INFO", pack=False, align=None), offset=0), "ppResponseInfo": SimTypePointer(SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "wResponseType": SimTypeShort(signed=False, label="UInt16"), "wResponseFlags": SimTypeShort(signed=False, label="UInt16"), "LastModifiedTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "dwMaxAge": SimTypeInt(signed=False, label="UInt32"), "pwszETag": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwProxyId": SimTypeInt(signed=False, label="UInt32")}, name="CRYPTNET_URL_CACHE_RESPONSE_INFO", pack=False, align=None), offset=0), offset=0), "pwszCacheFileNamePrefix": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pftCacheResync": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), "fProxyCacheRetrieval": SimTypeInt(signed=True, label="Int32"), "dwHttpStatusCode": SimTypeInt(signed=False, label="UInt32"), "ppwszErrorResponseHeaders": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppErrorContentBlob": SimTypePointer(SimTypePointer(SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), offset=0), offset=0)}, name="CRYPT_RETRIEVE_AUX_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszObjectOid", "dwRetrievalFlags", "dwTimeout", "ppvObject", "hAsyncRetrieve", "pCredentials", "pvVerify", "pAuxInfo"]),
        #
        'CryptRetrieveObjectByUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pszCredentialsOid": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pvCredentials": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="CRYPT_CREDENTIALS", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pLastSyncTime": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), "dwMaxUrlRetrievalByteCount": SimTypeInt(signed=False, label="UInt32"), "pPreFetchInfo": SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwObjectType": SimTypeInt(signed=False, label="UInt32"), "dwError": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32"), "ThisUpdateTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "NextUpdateTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "PublishTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None)}, name="CRYPTNET_URL_CACHE_PRE_FETCH_INFO", pack=False, align=None), offset=0), "pFlushInfo": SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwExemptSeconds": SimTypeInt(signed=False, label="UInt32"), "ExpireTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None)}, name="CRYPTNET_URL_CACHE_FLUSH_INFO", pack=False, align=None), offset=0), "ppResponseInfo": SimTypePointer(SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "wResponseType": SimTypeShort(signed=False, label="UInt16"), "wResponseFlags": SimTypeShort(signed=False, label="UInt16"), "LastModifiedTime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "dwMaxAge": SimTypeInt(signed=False, label="UInt32"), "pwszETag": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwProxyId": SimTypeInt(signed=False, label="UInt32")}, name="CRYPTNET_URL_CACHE_RESPONSE_INFO", pack=False, align=None), offset=0), offset=0), "pwszCacheFileNamePrefix": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pftCacheResync": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), "fProxyCacheRetrieval": SimTypeInt(signed=True, label="Int32"), "dwHttpStatusCode": SimTypeInt(signed=False, label="UInt32"), "ppwszErrorResponseHeaders": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppErrorContentBlob": SimTypePointer(SimTypePointer(SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), offset=0), offset=0)}, name="CRYPT_RETRIEVE_AUX_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszObjectOid", "dwRetrievalFlags", "dwTimeout", "ppvObject", "hAsyncRetrieve", "pCredentials", "pvVerify", "pAuxInfo"]),
        #
        'CryptInstallCancelRetrieval': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pvArg"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnCancel", "pvArg", "dwFlags", "pvReserved"]),
        #
        'CryptUninstallCancelRetrieval': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pvReserved"]),
        #
        'CryptGetObjectUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CRYPT_GET_URL_FLAGS"), SimTypePointer(SimStruct({"cUrl": SimTypeInt(signed=False, label="UInt32"), "rgwszUrl": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="CRYPT_URL_ARRAY", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwSyncDeltaTime": SimTypeInt(signed=False, label="UInt32"), "cGroup": SimTypeInt(signed=False, label="UInt32"), "rgcGroupEntry": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="CRYPT_URL_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrlOid", "pvPara", "dwFlags", "pUrlArray", "pcbUrlArray", "pUrlInfo", "pcbUrlInfo", "pvReserved"]),
    }

lib.set_prototypes(prototypes)
