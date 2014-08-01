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

    MODULE: asn1_pkimessage_export_api.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The Internal functions defined for ASN.1 objects

        *   ASN1_PKIMESSAGE
        *   ASN1_PKIHEADER
        *   ASN1_CMPGENERALINFO
        *   ASN1_PKIFREETEXT
        *   ASN1_PKIBODY
        *   ASN1_PKIPROTECTION
        *   ASN1_PROTECTEDPART
        *   ASN1_NESTEDMESSAGECONTENT
        *   ASN1_PKISTATUS
        *   ASN1_PKIFAILUREINFO
        *   ASN1_PKISTATUSINFO
        *   ASN1_OOBCERT
        *   ASN1_OOBCERTHASH
        *   ASN1_POPODECKEYCHALLCONTENT
        *   ASN1_CHALLENGE
        *   ASN1_POPODECKEYRESPCONTENT
        *   ASN1_CERTREPMESSAGE
        *   ASN1_CERTRESPONSES
        *   ASN1_RESPONSE
        *   ASN1_CERTIFIEDKEYPAIR
        *   ASN1_CERTORENCCERT
        *   ASN1_REVREQCONTENT
        *   ASN1_REVDETAILS
        *   ASN1_KEYRECREPCONTENT
        *   ASN1_CERTIFIEDKEYPAIRS
        *   ASN1_CAKEYUPDANNCONTENT
        *   ASN1_CERTANNCONTENT
        *   ASN1_REVANNCONTENT
        *   ASN1_CRLANNCONTENT
        *   ASN1_REVREPCONTENT
        *   ASN1_PKISTATUSINFOS
        *   ASN1_CERTIDS
        *   ASN1_CERTIFICATELISTS
        *   ASN1_PKICONFIRMCONTENT
        *   ASN1_INFOTYPEANDVALUE
        *   ASN1_ALGORITHMS
        *   ASN1_INFOVALUE
        *   ASN1_GENMSGCONTENT
        *   ASN1_GENREPCONTENT
        *   ASN1_ERRORMSGCONTENT
        *   ASN1_CERTCONFIRMCONTENT
        *   ASN1_CERTSTATUS


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


#ifndef  _ASN1_PKIMESSAGE_EXPORTED_API_H
#define  _ASN1_PKIMESSAGE_EXPORTED_API_H

/**********************************************************************

 OBJECT -- ASN1_PKIMESSAGE

 PKIMessage ::= Sequence 
     {
                            header PKIHeader 
                              body PKIBody 
                        protection [CON 0] PKIProtection OPT
                        extraCerts [CON 1] Certificates OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIMessage
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIHEADER

 PKIHeader ::= Sequence 
     {
                              pvno Integer 
                            sender GeneralName 
                         recipient GeneralName 
                       messageTime [CON 0] GeneralizedTime OPT
                     protectionAlg [CON 1] AlgorithmIdentifier OPT
                         senderKID [CON 2] KeyIdentifier OPT
                          recipKID [CON 3] KeyIdentifier OPT
                     transactionID [CON 4] OctetString OPT
                       senderNonce [CON 5] OctetString OPT
                        recipNonce [CON 6] OctetString OPT
                          freeText [CON 7] PKIFreeText OPT
                       generalInfo [CON 8] CMPGeneralInfo OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIHeader
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CMPGENERALINFO

 CMPGeneralInfo ::= SequenceOf InfoTypeAndValue  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCMPGeneralInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIFREETEXT

 PKIFreeText ::= SequenceOf UTF8String  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIFreeText
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIBODY

 PKIBody ::= Choice 
     {
                                ir [CON 0] CertReqMessages 
                                ip [CON 1] CertRepMessage 
                                cr [CON 2] CertReqMessages 
                                cp [CON 3] CertRepMessage 
                             p10cr [CON 4] CertificateRequest 
                           popdecc [CON 5] POPODecKeyChallContent 
                           popdecr [CON 6] POPODecKeyRespContent 
                               kur [CON 7] CertReqMessages 
                               kup [CON 8] CertRepMessage 
                               krr [CON 9] CertReqMessages 
                               krp [CON 10] KeyRecRepContent 
                                rr [CON 11] RevReqContent 
                                rp [CON 12] RevRepContent 
                               ccr [CON 13] CertReqMessages 
                               ccp [CON 14] CertRepMessage 
                            ckuann [CON 15] CAKeyUpdAnnContent 
                              cann [CON 16] CertAnnContent 
                              rann [CON 17] RevAnnContent 
                            crlann [CON 18] CRLAnnContent 
                              conf [CON 19] PKIConfirmContent 
                            nested [CON 20] NestedMessageContent 
                              genm [CON 21] GenMsgContent 
                              genp [CON 22] GenRepContent 
                             error [CON 23] ErrorMsgContent 
                          certConf CertConfirmContent 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIBody
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIPROTECTION

 PKIProtection ::= BitString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIProtection
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PROTECTEDPART

 ProtectedPart ::= Sequence 
     {
                            header PKIHeader 
                              body PKIBody 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateProtectedPart
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_NESTEDMESSAGECONTENT

 NestedMessageContent ::= PKIMessage 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateNestedMessageContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKISTATUS

 PKIStatus ::= Integer 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIStatus
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKIFAILUREINFO

 PKIFailureInfo ::= BitString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIFailureInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKISTATUSINFO

 PKIStatusInfo ::= Sequence 
     {
                            status PKIStatus 
                      statusString PKIFreeText OPT
                          failInfo PKIFailureInfo OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIStatusInfo
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_OOBCERT

 OOBCert ::= Certificate 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateOOBCert
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_OOBCERTHASH

 OOBCertHash ::= Sequence 
     {
                           hashAlg [CON 0] AlgorithmIdentifier OPT
                            certId [CON 1] CertId OPT
                           hashVal BitString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateOOBCertHash
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_POPODECKEYCHALLCONTENT

 POPODecKeyChallContent ::= SequenceOf Challenge  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePOPODecKeyChallContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CHALLENGE

 Challenge ::= Sequence 
     {
                               owf AlgorithmIdentifier OPT
                           witness OctetString 
                         challenge OctetString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateChallenge
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_POPODECKEYRESPCONTENT

 POPODecKeyRespContent ::= SequenceOf Integer  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePOPODecKeyRespContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTREPMESSAGE

 CertRepMessage ::= Sequence 
     {
                            caPubs [CON 1] Certificates OPT
                          response CertResponses 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertRepMessage
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTRESPONSES

 CertResponses ::= SequenceOf Response  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertResponses
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_RESPONSE

 Response ::= Sequence 
     {
                         certReqId Integer 
                            status PKIStatusInfo 
                  certifiedKeyPair CertifiedKeyPair OPT
                           rspInfo OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTIFIEDKEYPAIR

 CertifiedKeyPair ::= Sequence 
     {
                     certOrEncCert CertOrEncCert 
                        privateKey [CON 0] EncryptedValue OPT
                   publicationInfo [CON 1] PKIPublicationInfo OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertifiedKeyPair
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTORENCCERT

 CertOrEncCert ::= Choice 
     {
                       certificate [CON 0] Certificate 
                     encryptedCert [CON 1] EncryptedValue 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertOrEncCert
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REVREQCONTENT

 RevReqContent ::= SequenceOf RevDetails  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevReqContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REVDETAILS

 RevDetails ::= Sequence 
     {
                       certDetails CertTemplate 
                  revocationReason ReasonFlags OPT
                      badSinceDate GeneralizedTime OPT
                   crlEntryDetails Extensions OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevDetails
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_KEYRECREPCONTENT

 KeyRecRepContent ::= Sequence 
     {
                            status PKIStatusInfo 
                        newSigCert [CON 0] Certificate OPT
                           caCerts [CON 1] Certificates OPT
                       keyPairHist [CON 2] CertifiedKeyPairs 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateKeyRecRepContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTIFIEDKEYPAIRS

 CertifiedKeyPairs ::= SequenceOf CertifiedKeyPair  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertifiedKeyPairs
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CAKEYUPDANNCONTENT

 CAKeyUpdAnnContent ::= Sequence 
     {
                        oldWithNew Certificate 
                        newWithOld Certificate 
                        newWithNew Certificate 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCAKeyUpdAnnContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTANNCONTENT

 CertAnnContent ::= Certificate 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertAnnContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REVANNCONTENT

 RevAnnContent ::= Sequence 
     {
                            status PKIStatus 
                            certId CertId 
                   willBeRevokedAt GeneralizedTime 
                      badSinceDate GeneralizedTime 
                        crlDetails Extensions OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevAnnContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CRLANNCONTENT

 CRLAnnContent ::= SequenceOf CertificateList  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCRLAnnContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REVREPCONTENT

 RevRepContent ::= Sequence 
     {
                            status PKIStatusInfos 
                          revCerts [CON 0] CertIds OPT
                              crls [CON 1] CertificateLists OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevRepContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKISTATUSINFOS

 PKIStatusInfos ::= SequenceOf PKIStatusInfo  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIStatusInfos
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTIDS

 CertIds ::= SequenceOf CertId  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertIds
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTIFICATELISTS

 CertificateLists ::= SequenceOf CertificateList  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertificateLists
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PKICONFIRMCONTENT

 PKIConfirmContent ::= NULL 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePKIConfirmContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_INFOTYPEANDVALUE

 InfoTypeAndValue ::= Sequence 
     {
                          infoType OID 
                         infoValue InfoValue 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateInfoTypeAndValue
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ALGORITHMS

 Algorithms ::= SequenceOf AlgorithmIdentifier  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAlgorithms
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_INFOVALUE

 InfoValue ::= Choice 
     {
                     caProtEncCert Certificate 
                  signKeyPairTypes Algorithms 
                   encKeyPairTypes Algorithms 
                  preferredSymmAlg AlgorithmIdentifier 
                   caKeyUpdateInfo CAKeyUpdAnnContent 
                        currentCRL CertificateList 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateInfoValue
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_GENMSGCONTENT

 GenMsgContent ::= SequenceOf InfoTypeAndValue  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateGenMsgContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_GENREPCONTENT

 GenRepContent ::= SequenceOf InfoTypeAndValue  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateGenRepContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ERRORMSGCONTENT

 ErrorMsgContent ::= Sequence 
     {
                     pKIStatusInfo PKIStatusInfo 
                         errorCode Integer OPT
                      errorDetails PKIFreeText 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateErrorMsgContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTCONFIRMCONTENT

 CertConfirmContent ::= SequenceOf CertStatus  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertConfirmContent
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CERTSTATUS

 CertStatus ::= Sequence 
     {
                          certHash OctetString 
                         certReqId Integer 
                        statusInfo PKIStatusInfo OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertStatus
    (
        ANSC_HANDLE                 hReserved
    );


#endif  /* _ASN1_PKIMESSAGE_EXPORTED_API_H */
