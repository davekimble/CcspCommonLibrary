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

    MODULE: asn1_certreqmsg_export_api.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The Internal functions defined for ASN.1 objects

        *   ASN1_CERTREQMSG
        *   ASN1_CERTREQMESSAGES
        *   ASN1_REGINFO
        *   ASN1_CERTREQUEST
        *   ASN1_CERTTEMPLATE
        *   ASN1_OPTIONALVALIDITY
        *   ASN1_CONTROLS
        *   ASN1_CRMFATTRTYPEANDVALUE
        *   ASN1_PROOFOFPOSSESSION
        *   ASN1_POPOSIGNINGKEY
        *   ASN1_POPOSIGNINGKEYINPUT
        *   ASN1_AUTHINFO
        *   ASN1_PKMACVALUE
        *   ASN1_POPOPRIVKEY
        *   ASN1_SUBSEQUENTMESSAGE
        *   ASN1_REGTOKEN
        *   ASN1_AUTHENTICATOR
        *   ASN1_PKIPUBLICATIONINFO
        *   ASN1_PUBINFOS
        *   ASN1_SINGLEPUBINFO
        *   ASN1_PKIARCHIVEOPTIONS
        *   ASN1_ENCRYPTEDKEY
        *   ASN1_ENCRYPTEDVALUE
        *   ASN1_KEYGENPARAMETERS
        *   ASN1_CERTID
        *   ASN1_PROTOCOLENCRKEY
        *   ASN1_CRMFATTRVALUE


    ---------------------------------------------------------------

    ENVIRONMENT:

        platform independent

    ---------------------------------------------------------------

    AUTHOR:

        ASNMAGIC ANSC CODE GENERATOR 1.0

    ---------------------------------------------------------------

    REVISION HISTORY:

        *   12/13/2002  initial revision

 **********************************************************************/


#ifndef  _ASN1_CERTREQMSG_EXPORTED_API_H
#define  _ASN1_CERTREQMSG_EXPORTED_API_H

/**********************************************************************

 OBJECT -- ASN1_CERTREQMSG

 CertReqMsg ::= Sequence 
     {
                           certReq CertRequest 
                               pop ProofOfPossession OPT
                           regInfo RegInfo OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertReqMsg
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTREQMESSAGES

 CertReqMessages ::= SequenceOf CertReqMsg  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertReqMessages
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REGINFO

 RegInfo ::= SequenceOf CRMFAttrTypeAndValue  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRegInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTREQUEST

 CertRequest ::= Sequence 
     {
                         certReqId Integer 
                      certTemplate CertTemplate 
                          controls Controls OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTTEMPLATE

 CertTemplate ::= Sequence 
     {
                           version [CON 0] IMP Integer OPT
                      serialNumber [CON 1] IMP Integer OPT
                        signingAlg [CON 2] IMP AlgorithmIdentifier OPT
                            issuer [CON 3] IMP Name OPT
                          validity [CON 4] IMP OptionalValidity OPT
                           subject [CON 5] IMP Name OPT
                         publicKey [CON 6] IMP SubjectPublicKeyInfo OPT
                         issuerUID [CON 7] IMP UniqueIdentifier OPT
                        subjectUID [CON 8] IMP UniqueIdentifier OPT
                        extensions [CON 9] IMP Extensions OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertTemplate
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_OPTIONALVALIDITY

 OptionalValidity ::= Sequence 
     {
                         notBefore [CON 0] IMP Time OPT
                          notAfter [CON 1] IMP Time OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateOptionalValidity
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CONTROLS

 Controls ::= SequenceOf CRMFAttrTypeAndValue  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateControls
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CRMFATTRTYPEANDVALUE

 CRMFAttrTypeAndValue ::= Sequence 
     {
                          crmfType OID 
                             value CRMFAttrValue 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCRMFAttrTypeAndValue
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PROOFOFPOSSESSION

 ProofOfPossession ::= Choice 
     {
                        raVerified [CON 0] IMP NULL 
                         signature [CON 1] IMP POPOSigningKey 
                   keyEncipherment [CON 2] IMP POPOPrivKey 
                      keyAgreement [CON 3] IMP POPOPrivKey OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateProofOfPossession
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_POPOSIGNINGKEY

 POPOSigningKey ::= Sequence 
     {
                       poposkInput [CON 0] IMP POPOSigningKeyInput OPT
               algorithmIdentifier AlgorithmIdentifier 
                         signature BitString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePOPOSigningKey
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_POPOSIGNINGKEYINPUT

 POPOSigningKeyInput ::= Sequence 
     {
                          authInfo AuthInfo 
                         publicKey SubjectPublicKeyInfo 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePOPOSigningKeyInput
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_AUTHINFO

 AuthInfo ::= Choice 
     {
                            sender [CON 0] IMP GeneralName 
                      publicKeyMAC PKMACValue 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAuthInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKMACVALUE

 PKMACValue ::= Sequence 
     {
                             algId AlgorithmIdentifier 
                             value BitString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKMACValue
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_POPOPRIVKEY

 POPOPrivKey ::= Choice 
     {
                       thisMessage [CON 0] IMP BitString 
                 subsequentMessage [CON 1] IMP SubsequentMessage 
                             dhMAC [CON 2] IMP BitString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePOPOPrivKey
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SUBSEQUENTMESSAGE

 SubsequentMessage ::= Integer 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSubsequentMessage
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REGTOKEN

 RegToken ::= UTF8String 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRegToken
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_AUTHENTICATOR

 Authenticator ::= UTF8String 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAuthenticator
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIPUBLICATIONINFO

 PKIPublicationInfo ::= Sequence 
     {
                            action Integer 
                          pubInfos PubInfos OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIPublicationInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PUBINFOS

 PubInfos ::= SequenceOf SinglePubInfo  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePubInfos
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SINGLEPUBINFO

 SinglePubInfo ::= Sequence 
     {
                         pubMethod Integer 
                       pubLocation GeneralName OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSinglePubInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIARCHIVEOPTIONS

 PKIArchiveOptions ::= Choice 
     {
                  encryptedPrivKey [CON 0] IMP EncryptedKey 
                  keyGenParameters [CON 1] IMP KeyGenParameters 
              archiveRemGenPrivKey [CON 2] IMP BOOL 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIArchiveOptions
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ENCRYPTEDKEY

 EncryptedKey ::= Choice 
     {
                    encryptedValue EncryptedValue 
                     envelopedData [CON 0] IMP EnvelopedData 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateEncryptedKey
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ENCRYPTEDVALUE

 EncryptedValue ::= Sequence 
     {
                       intendedAlg [CON 0] IMP AlgorithmIdentifier OPT
                           symmAlg [CON 1] IMP AlgorithmIdentifier OPT
                        encSymmKey [CON 2] IMP BitString OPT
                            keyAlg [CON 3] IMP AlgorithmIdentifier OPT
                         valueHint [CON 4] IMP OctetString OPT
                          encValue BitString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateEncryptedValue
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_KEYGENPARAMETERS

 KeyGenParameters ::= OctetString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateKeyGenParameters
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTID

 CertId ::= Sequence 
     {
                            issuer GeneralName 
                      serialNumber Integer 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertId
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PROTOCOLENCRKEY

 ProtocolEncrKey ::= SubjectPublicKeyInfo 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateProtocolEncrKey
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CRMFATTRVALUE

 CRMFAttrValue ::= Choice 
     {
                          regToken RegToken 
                     authenticator Authenticator 
                pkiPublicationInfo PKIPublicationInfo 
                 pkiArchiveOptions PKIArchiveOptions 
                         oldCertId CertId 
                   protocolEncrKey ProtocolEncrKey 
                         utf8Pairs UTF8String 
                           certReq CertRequest 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCRMFAttrValue
    (
        ANSC_HANDLE                 hReserved
    );


#endif  /* _ASN1_CERTREQMSG_EXPORTED_API_H */
