/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**********************************************************************

    MODULE: ansc_asn1_PrivateKeyInfo_internal.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The Internal functions defined for ASN.1 objects

        *   ANSC_ASN1_ENCRYPTEDPRIVATEKEYINFO
        *   ANSC_ASN1_ENCRYPTIONALGORITHMIDENTIFIER
        *   ANSC_ASN1_PRIVATEKEYINFO
        *   ANSC_ASN1_PRIVATEKEY
        *   ANSC_ASN1_RSAPRIVATEKEY
        *   ANSC_ASN1_DSAPRIVATEKEY


    ---------------------------------------------------------------

    ENVIRONMENT:

        platform independent

    ---------------------------------------------------------------

    AUTHOR:

        ASNMAGIC ANSC CODE GENERATOR 1.0

    ---------------------------------------------------------------

    REVISION HISTORY:

        *   05/01/2002  initial revision

 **********************************************************************/


#ifndef  _ANSC_ASN1_PRIVATEKEYINFO_INTERNAL_H
#define  _ANSC_ASN1_PRIVATEKEYINFO_INTERNAL_H

/**********************************************************************

 OBJECT -- ANSC_ASN1_ENCRYPTEDPRIVATEKEYINFO

 EncryptedPrivateKeyInfo ::= Sequence 
     {
               encryptionAlgorithm EncryptionAlgorithmIdentifier 
                     encryptedData OctetString 
         EXTRA:
                     privateKeyInfo PrivateKeyInfo 
     }

 **********************************************************************/

PANSC_ATTR_OBJECT
AnscAsn1EncryptedPrivateKeyInfoCreateChildAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PCHAR
AnscAsn1EncryptedPrivateKeyInfoGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

ANSC_HANDLE
AnscAsn1EncryptedPrivateKeyInfoCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

ANSC_HANDLE
AnscAsn1EncryptedPrivateKeyInfoGetEncryptionAlgorithm
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_HANDLE
AnscAsn1EncryptedPrivateKeyInfoGetEncryptedData
    (
        ANSC_HANDLE                 hThisObject
    );

PCHAR
AnscAsn1EncryptedPrivateKeyInfoGetExtraChildName
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_HANDLE
AnscAsn1EncryptedPrivateKeyInfoCreateExtraChild
    (
        ANSC_HANDLE                 hThisObject
    );

/**********************************************************************

 OBJECT -- ANSC_ASN1_ENCRYPTIONALGORITHMIDENTIFIER

 EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier 

 **********************************************************************/

 /* No internal function is required for this object. */    

/**********************************************************************

 OBJECT -- ANSC_ASN1_PRIVATEKEYINFO

 PrivateKeyInfo ::= Sequence 
     {
                           version Integer 
               privateKeyAlgorithm AlgorithmIdentifier 
                   privateKeyOctet OctetString 
                        attributes [CON 0] IMP Attributes OPT
         EXTRA:
                         privateKey PrivateKey 
     }

 **********************************************************************/

PANSC_ATTR_OBJECT
AnscAsn1PrivateKeyInfoCreateChildAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PCHAR
AnscAsn1PrivateKeyInfoGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

ANSC_HANDLE
AnscAsn1PrivateKeyInfoCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PCHAR
AnscAsn1PrivateKeyInfoGetExtraChildName
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_HANDLE
AnscAsn1PrivateKeyInfoCreateExtraChild
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 *  Manually added funtions
 */
BOOLEAN
AnscAsn1PrivateKeyInfoInitKey
    (
        ANSC_HANDLE                 hThisObject,
        PKI_KEY_TYPE                keyType,
        ANSC_HANDLE                 hKeyGenHandle
    );

ANSC_STATUS
AnscAsn1PrivateKeyInfoExportKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

ANSC_STATUS
AnscAsn1PrivateKeyInfoAfterDeocdingChild
    (
        ANSC_HANDLE                 hThisObject,
        int                         index,
        PVOID*                      ppEncoding
    );

ANSC_STATUS
AnscAsn1PrivateKeyInfoSignData
    (
        ANSC_HANDLE                 pCryptHandle,
        PUCHAR                      pDataWillBeSigned,
        ULONG                       lengthOfData,
        SIGNATURE_TYPE              SignatureType,
        PUCHAR                      pDataSigned,
        PULONG                      pLength
    );

ANSC_STATUS
AnscAsn1PrivateKeyInfoDecryptData
    (
        ANSC_HANDLE                 pCryptHandle ,
        PUCHAR                      pDataWillBeDecrypted,
        ULONG                       lengthOfData,
        PUCHAR                      pDataDecrypted,
        PULONG                      pLength
    );

PKI_KEY_TYPE
AnscAsn1PrivateKeyInfoGetKeyType
    (
        ANSC_HANDLE                 hThisObject
    );

/**********************************************************************

 OBJECT -- ANSC_ASN1_PRIVATEKEY

 PrivateKey ::= Choice 
     {
                     rsaPrivateKey RSAPrivateKey 
                     dsaPrivateKey DSAPrivateKey 
     }

 **********************************************************************/

ANSC_HANDLE
AnscAsn1PrivateKeyCreateSelection
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PANSC_ATTR_OBJECT
AnscAsn1PrivateKeyCreateSelectionAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       selType
    );

PCHAR
AnscAsn1PrivateKeyGetSelectionName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       selType
    );

BOOLEAN
AnscAsn1PrivateKeyGetChoiceTagValue
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       uIndex,
        PASN_OBJECT_FORM_TYPE       pAttr,
        PULONG                      pTagValue
    );

/*
 *  manually added functions
 */
ANSC_STATUS
AnscAsn1PrivateKeyDecryptData
    (
        ANSC_HANDLE                 pCryptHandle ,
        PUCHAR                      pDataWillBeDecrypted,
        ULONG                       lengthOfData,
        PUCHAR                      pDataDecrypted,
        PULONG                      pLength
    );

BOOLEAN
AnscAsn1PrivateKeyInitKey
    (
        ANSC_HANDLE                 hThisObject,
        PKI_KEY_TYPE                keyType,
        ANSC_HANDLE                 hKeyGenHandle
    );

ANSC_STATUS
AnscAsn1PrivateKeyExportKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

/**********************************************************************

 OBJECT -- ANSC_ASN1_RSAPRIVATEKEY

 RSAPrivateKey ::= Sequence 
     {
                           version Integer 
                           modulus Integer 
                    publicExponent Integer 
                   privateExponent Integer 
                            prime1 Integer 
                            prime2 Integer 
                         exponent1 Integer 
                         exponent2 Integer 
                       coefficient Integer 
     }

 **********************************************************************/

PANSC_ATTR_OBJECT
AnscAsn1RSAPrivateKeyCreateChildAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PCHAR
AnscAsn1RSAPrivateKeyGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

ANSC_HANDLE
AnscAsn1RSAPrivateKeyCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );


/*
 *  manually added functions
 */
ANSC_STATUS
AnscAsn1RSAPrivateKeyDecryptData
    (
        ANSC_HANDLE                 pCryptHandle ,
        PUCHAR                      pDataWillBeDecrypted,
        ULONG                       lengthOfData,
        PUCHAR                      pDataDecrypted,
        PULONG                      pLength
    );

BOOLEAN
AnscAsn1RSAPrivateKeyInitKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

ANSC_STATUS
AnscAsn1RSAPrivateKeyExportKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

/**********************************************************************

 OBJECT -- ANSC_ASN1_DSAPRIVATEKEY

 DSAPrivateKey ::= Sequence 
     {
                                 y Integer 
                                 x Integer 
     }

 **********************************************************************/

PANSC_ATTR_OBJECT
AnscAsn1DSAPrivateKeyCreateChildAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

PCHAR
AnscAsn1DSAPrivateKeyGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

ANSC_HANDLE
AnscAsn1DSAPrivateKeyCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    );

/*
 *  manually added functions
 */
BOOLEAN
AnscAsn1DSAPrivateKeyInitKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

ANSC_STATUS
AnscAsn1DSAPrivateKeyExportKey
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hKeyGenHandle
    );

#endif  /*_ANSC_ASN1_PRIVATEKEYINFO_INTERNAL_H*/

