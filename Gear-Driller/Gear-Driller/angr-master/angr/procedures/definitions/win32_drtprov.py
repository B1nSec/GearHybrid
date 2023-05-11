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
lib.set_library_names("drtprov.dll")
prototypes = \
    {
        #
        'DrtCreatePnrpBootstrapResolver': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "InitResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "IssueResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Register": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Unregister": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_BOOTSTRAP_PROVIDER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fPublish", "pwzPeerName", "pwzCloudName", "pwzPublishingIdentity", "ppResolver"]),
        #
        'DrtDeletePnrpBootstrapResolver': SimTypeFunction([SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "InitResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "IssueResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Register": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Unregister": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_BOOTSTRAP_PROVIDER", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResolver"]),
        #
        'DrtCreateDnsBootstrapResolver': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "InitResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "IssueResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Register": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Unregister": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_BOOTSTRAP_PROVIDER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["port", "pwszAddress", "ppModule"]),
        #
        'DrtDeleteDnsBootstrapResolver': SimTypeFunction([SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "InitResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "IssueResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndResolve": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Register": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Unregister": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_BOOTSTRAP_PROVIDER", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResolver"]),
        #
        'DrtCreateDerivedKeySecurityProvider': SimTypeFunction([SimTypePointer(SimStruct({"dwCertEncodingType": SimTypeInt(signed=False, label="UInt32"), "pbCertEncoded": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cbCertEncoded": SimTypeInt(signed=False, label="UInt32"), "pCertInfo": SimTypePointer(SimStruct({"dwVersion": SimTypeInt(signed=False, label="UInt32"), "SerialNumber": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SignatureAlgorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "Issuer": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "NotBefore": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "NotAfter": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "Subject": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SubjectPublicKeyInfo": SimStruct({"Algorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "PublicKey": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None)}, name="CERT_PUBLIC_KEY_INFO", pack=False, align=None), "IssuerUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "SubjectUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "cExtension": SimTypeInt(signed=False, label="UInt32"), "rgExtension": SimTypePointer(SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "fCritical": SimTypeInt(signed=True, label="Int32"), "Value": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CERT_EXTENSION", pack=False, align=None), offset=0)}, name="CERT_INFO", pack=False, align=None), offset=0), "hCertStore": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="CERT_CONTEXT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"dwCertEncodingType": SimTypeInt(signed=False, label="UInt32"), "pbCertEncoded": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cbCertEncoded": SimTypeInt(signed=False, label="UInt32"), "pCertInfo": SimTypePointer(SimStruct({"dwVersion": SimTypeInt(signed=False, label="UInt32"), "SerialNumber": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SignatureAlgorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "Issuer": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "NotBefore": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "NotAfter": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "Subject": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SubjectPublicKeyInfo": SimStruct({"Algorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "PublicKey": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None)}, name="CERT_PUBLIC_KEY_INFO", pack=False, align=None), "IssuerUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "SubjectUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "cExtension": SimTypeInt(signed=False, label="UInt32"), "rgExtension": SimTypePointer(SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "fCritical": SimTypeInt(signed=True, label="Int32"), "Value": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CERT_EXTENSION", pack=False, align=None), offset=0)}, name="CERT_INFO", pack=False, align=None), offset=0), "hCertStore": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="CERT_CONTEXT", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "RegisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UnregisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateAndUnpackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SecureAndPackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "FreeData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EncryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DecryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "GetSerializedCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateRemoteCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SignData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "VerifyData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_SECURITY_PROVIDER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRootCert", "pLocalCert", "ppSecurityProvider"]),
        #
        'DrtCreateDerivedKey': SimTypeFunction([SimTypePointer(SimStruct({"dwCertEncodingType": SimTypeInt(signed=False, label="UInt32"), "pbCertEncoded": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cbCertEncoded": SimTypeInt(signed=False, label="UInt32"), "pCertInfo": SimTypePointer(SimStruct({"dwVersion": SimTypeInt(signed=False, label="UInt32"), "SerialNumber": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SignatureAlgorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "Issuer": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "NotBefore": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "NotAfter": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "Subject": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None), "SubjectPublicKeyInfo": SimStruct({"Algorithm": SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Parameters": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CRYPT_ALGORITHM_IDENTIFIER", pack=False, align=None), "PublicKey": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None)}, name="CERT_PUBLIC_KEY_INFO", pack=False, align=None), "IssuerUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "SubjectUniqueId": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cUnusedBits": SimTypeInt(signed=False, label="UInt32")}, name="CRYPT_BIT_BLOB", pack=False, align=None), "cExtension": SimTypeInt(signed=False, label="UInt32"), "rgExtension": SimTypePointer(SimStruct({"pszObjId": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "fCritical": SimTypeInt(signed=True, label="Int32"), "Value": SimStruct({"cbData": SimTypeInt(signed=False, label="UInt32"), "pbData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CRYPTOAPI_BLOB", pack=False, align=None)}, name="CERT_EXTENSION", pack=False, align=None), offset=0)}, name="CERT_INFO", pack=False, align=None), offset=0), "hCertStore": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="CERT_CONTEXT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"cb": SimTypeInt(signed=False, label="UInt32"), "pb": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DRT_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pLocalCert", "pKey"]),
        #
        'DrtDeleteDerivedKeySecurityProvider': SimTypeFunction([SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "RegisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UnregisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateAndUnpackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SecureAndPackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "FreeData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EncryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DecryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "GetSerializedCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateRemoteCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SignData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "VerifyData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_SECURITY_PROVIDER", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pSecurityProvider"]),
        #
        'DrtCreateNullSecurityProvider': SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "RegisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UnregisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateAndUnpackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SecureAndPackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "FreeData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EncryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DecryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "GetSerializedCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateRemoteCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SignData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "VerifyData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_SECURITY_PROVIDER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSecurityProvider"]),
        #
        'DrtDeleteNullSecurityProvider': SimTypeFunction([SimTypePointer(SimStruct({"pvContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Attach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Detach": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "RegisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UnregisterKey": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateAndUnpackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SecureAndPackPayload": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "FreeData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EncryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DecryptData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "GetSerializedCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "ValidateRemoteCredential": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SignData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "VerifyData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DRT_SECURITY_PROVIDER", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pSecurityProvider"]),
    }

lib.set_prototypes(prototypes)
