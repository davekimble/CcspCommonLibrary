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

    MODULE: ansc_asn1_CRL.c

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The ASN.1 objects implemented in this file

        *   ANSC_ASN1_CRL
        *   ANSC_ASN1_TBSCERTLIST
        *   ANSC_ASN1_REVOKEDCERTIFICATE
        *   ANSC_ASN1_REVOKEDCERTIFICATES
        *   ANSC_ASN1_SIGNATURE
        *   ANSC_ASN1_CERTIFICATELIST


    ---------------------------------------------------------------

    ENVIRONMENT:

        platform independent

    ---------------------------------------------------------------

    AUTHOR:

        ASNMAGIC ANSC CODE GENERATOR 1.0

    ---------------------------------------------------------------

    REVISION HISTORY:

        *   05/07/2002  initial revision

 **********************************************************************/


#include "ansc_asn1_advanced_local.h"

/**********************************************************************

 OBJECT -- ANSC_ASN1_CRL

 CRL ::= Sequence 
     {
                       tbsCertList TBSCertList 
                 sigatureAlgorithm SignatureAlgorithmIdentifier 
                         signature Signature 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCRL
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_CRL                  pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_CRL)
        AnscAsn1CreateSequence
            (
                (ANSC_HANDLE)sizeof(ANSC_ASN1_CRL)
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_CRL");
    pThisObject->SetName(pThisObject, "CRL");

    pThisObject->Create             = AnscAsn1CreateCRL;
    pThisObject->AsnFree            = AnscAsn1CRLFree;
    pThisObject->GetChildName       = AnscAsn1CRLGetChildName;
    pThisObject->CreateChildObject  = AnscAsn1CRLCreateChildObject;
    pThisObject->GetTbsCertList     = AnscAsn1CRLGetTbsCertList;
    pThisObject->GetSigatureAlgorithm
                                    = AnscAsn1CRLGetSigatureAlgorithm;
    pThisObject->GetSignature       = AnscAsn1CRLGetSignature;

    pThisObject->GetIssuerHandle    = AnscAsn1CRLGetIssuerHandle;
    pThisObject->GetThisUpdateTime  = AnscAsn1CRLGetThisUpdateTime;
    pThisObject->GetNextUpdateTime  = AnscAsn1CRLGetNextUpdateTime;
    pThisObject->Verify             = AnscAsn1CRLVerify;
    pThisObject->IsCertRevoked      = AnscAsn1CRLIsCertRevoked;
    pThisObject->EnumRevokedCert    = AnscAsn1CRLEnumRevokedCert;
    pThisObject->GetSignatureType   = AnscAsn1CRLGetSignatureType;
    pThisObject->IsCRLExpired       = AnscAsn1CRLIsCRLExpired;
    pThisObject->BeforeDecodingChild
                                    = AnscAsn1CRLBeforeDecodingChild;
    pThisObject->AfterDecodingChild = AnscAsn1CRLAfterDecodingChild;

    pThisObject->pSignedData        = NULL;
    pThisObject->uSignedLength      = 0;

    pThisObject->uTotalChild        = 3;

    /*
     * Create all the children
     */
    pThisObject->CreateAllChildren(pThisObject);


    return (ANSC_HANDLE)pThisObject;
}

ANSC_STATUS
AnscAsn1CRLFree
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pBaseObject  = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_OBJECT               pChild       = NULL;

    if( pBaseObject != NULL)
    {
        /* free the signed data part */
        if( pBaseObject->pSignedData != NULL && pBaseObject->uSignedLength > 0)
        {
            AnscFreeMemory(pBaseObject->pSignedData);
        }

        /*
         *  Remove the children here, from the end;
         */
        pBaseObject->RemoveAllChildren(pBaseObject,TRUE);

        /*
         *  Remove the extra child;
         */
        pChild = pBaseObject->pExtraChild;

        if( pChild != NULL)
        {
            pChild->AsnFree(pChild);
        }

        AttrListRemoveAllAttributes(&pBaseObject->sAttrList);

        if( pBaseObject->Name != NULL)
        {
            AnscFreeMemory(pBaseObject->Name);
        }

        if( pBaseObject->ClassName != NULL)
        {
            AnscFreeMemory(pBaseObject->ClassName);
        }

        AnscFreeMemory(pBaseObject);
    }

    return  ANSC_STATUS_SUCCESS;
}

ANSC_HANDLE
AnscAsn1CRLCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    PANSC_ASN1_OBJECT               pThisObject      = NULL;
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    switch( index )
    {

        case 0:

            pThisObject = AnscAsn1CreateTBSCertList(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 1:

            pThisObject = AnscAsn1CreateSignatureAlgorithmIdentifier(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 2:

            pThisObject = AnscAsn1CreateSignature(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

    }

    return pThisObject;

}

PCHAR
AnscAsn1CRLGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    switch ( index )
    {
        case 0:

            return"tbsCertList";

        case 1:

            return"sigatureAlgorithm";

        case 2:

            return"signature";

    }

    return "";

}

ANSC_HANDLE
AnscAsn1CRLGetTbsCertList
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    return pParent->GetChildByIndex(pParent, 0);

}

ANSC_HANDLE
AnscAsn1CRLGetSigatureAlgorithm
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    return pParent->GetChildByIndex(pParent, 1);

}

ANSC_HANDLE
AnscAsn1CRLGetSignature
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    return pParent->GetChildByIndex(pParent, 2);

}

/*
 *  Manually added functions
 */
ANSC_STATUS
AnscAsn1CRLBeforeDecodingChild
    (
        ANSC_HANDLE                 hThisObject,
        int                         index,
        PVOID*                      ppEncoding
    )
{
    PANSC_ASN1_CRL                  pThisObject  = (PANSC_ASN1_CRL)hThisObject;

    if( pThisObject != NULL && index == 0)
    {
        /* free the signed data part */
        if( pThisObject->pSignedData != NULL && pThisObject->uSignedLength > 0)
        {
            AnscFreeMemory(pThisObject->pSignedData);
        }

        pThisObject->pSignedData    = *ppEncoding;
        pThisObject->uSignedLength  = 0;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
AnscAsn1CRLAfterDecodingChild
    (
        ANSC_HANDLE                 hThisObject,
        int                         index,
        PVOID*                      ppEncoding
    )
{
    PANSC_ASN1_CRL                  pThisObject  = (PANSC_ASN1_CRL)hThisObject;
    PUCHAR                          pEndBuffer   = *ppEncoding;
    PUCHAR                          pBack;

    if( pThisObject != NULL && index == 0)
    {
        pThisObject->uSignedLength  = pEndBuffer - pThisObject->pSignedData;

        /* make a copy here */
        pBack = pThisObject->pSignedData;

        pThisObject->pSignedData
            = (PUCHAR)AnscAllocateMemory(pThisObject->uSignedLength + 8);

        if( pThisObject->pSignedData != NULL)
        {
            AnscCopyMemory
                (
                    pThisObject->pSignedData,
                    pBack,
                    pThisObject->uSignedLength
                );
        }
        else
        {
            pThisObject->uSignedLength = 0;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_HANDLE
AnscAsn1CRLGetIssuerHandle
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pCRL        = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TBSCERTLIST          pTBSList;

    if( pCRL == NULL)
    {
        return NULL;
    }

    pTBSList = (PANSC_ASN1_TBSCERTLIST)pCRL->GetTbsCertList(pCRL);

    if( pTBSList == NULL)
    {
        return NULL;
    }

    return pTBSList->GetChildByIndex(pTBSList,2);
}

ANSC_HANDLE
AnscAsn1CRLGetThisUpdateTime
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pCRL        = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TBSCERTLIST          pTBSList;

    if( pCRL == NULL)
    {
        return NULL;
    }

    pTBSList = (PANSC_ASN1_TBSCERTLIST)pCRL->GetTbsCertList(pCRL);

    if( pTBSList == NULL)
    {
        return NULL;
    }

    return pTBSList->GetChildByIndex(pTBSList,3);
}

ANSC_HANDLE
AnscAsn1CRLGetNextUpdateTime
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pCRL        = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TBSCERTLIST          pTBSList;

    if( pCRL == NULL)
    {
        return NULL;
    }

    pTBSList = (PANSC_ASN1_TBSCERTLIST)pCRL->GetTbsCertList(pCRL);

    if( pTBSList == NULL)
    {
        return NULL;
    }

    return pTBSList->GetChildByIndex(pTBSList,4);
}

BOOLEAN
AnscAsn1CRLVerify
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPublicKeyInfo
    )
{
    PANSC_ASN1_CRL                  pThisObject     = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_RSAPUBLICKEY         pRSAKey         = NULL;
    PANSC_ASN1_PUBLICKEY            pPublicKey      = NULL;
    PANSC_ASN1_SUBJECTPUBLICKEYINFO pPublicKeyInfo;
    PANSC_ASN1_OBJECT               pKeyObject;
    PANSC_ASN1_OBJECT               pSelection;
    PANSC_ASN1_BITSTRING            pBitString;
    PANSC_ASN1_TBSCERTLIST          pTBSCert;
    PUCHAR                          pSignature;
    ANSC_STATUS                     status;

    if( pThisObject == NULL || hPublicKeyInfo == NULL)
    {
        return FALSE;
    }

    /* check the public key */
    pKeyObject = (PANSC_ASN1_OBJECT)hPublicKeyInfo;

    if( AnscEqualString1(pKeyObject->ClassName,"ANSC_ASN1_RSAPUBLICKEY",FALSE))
    {
        pRSAKey = (PANSC_ASN1_RSAPUBLICKEY)pKeyObject;
    }
    else if( AnscEqualString1(pKeyObject->ClassName,"ANSC_ASN1_PUBLICKEY",FALSE))
    {
        pPublicKey  = (PANSC_ASN1_PUBLICKEY)pKeyObject;
        pSelection  = (PANSC_ASN1_OBJECT)pPublicKey->hSelection;

        if( pSelection == NULL || 
            !AnscEqualString1(pSelection->ClassName,"ANSC_ASN1_RSAPUBLICKEY", FALSE))
        {
            return FALSE;
        }

        pRSAKey = (PANSC_ASN1_RSAPUBLICKEY)pSelection;
    }
    else
    {
        pPublicKeyInfo  =(PANSC_ASN1_SUBJECTPUBLICKEYINFO)hPublicKeyInfo;
    }

    /* get the data to be verified */
    if( pThisObject->pSignedData == NULL || pThisObject->uSignedLength == 0)
    {
        pTBSCert    = (PANSC_ASN1_TBSCERTLIST)pThisObject->GetTbsCertList(pThisObject);

        pThisObject->pSignedData = 
            pTBSCert->GetEncodedData
                (
                    pTBSCert,
                    &pThisObject->uSignedLength
                );
    }

    if( pThisObject->pSignedData == NULL || pThisObject->uSignedLength == 0)
    {
        return FALSE;
    }

    /* get the signature object */
    pBitString = pThisObject->GetSignature(pThisObject);

    if( pBitString->uLength <= 4)
    {
        AnscTrace("Invalid signature (len = %s)\n", pBitString->uLength);

        return FALSE;
    }

    if( pBitString->bIsDynamic)
    {
        pSignature = pBitString->pStringBuffer;
    }
    else
    {
        pSignature = pBitString->pString;
    }

    /* verify now */
    if( pRSAKey != NULL)
    {
        status =
            pRSAKey->Verify
                (
                    pRSAKey,
                    NULL,
                    pThisObject->pSignedData,
                    pThisObject->uSignedLength,
                    pThisObject->GetSignatureType(pThisObject),
                    pSignature,
                    pBitString->uLength
                );
    }
    else
    {
        status =
            pPublicKeyInfo->Verify
                (
                    pPublicKeyInfo,
                    pThisObject->pSignedData,
                    pThisObject->uSignedLength,
                    pThisObject->GetSignatureType(pThisObject),
                    pSignature,
                    pBitString->uLength
                );
    }

    return (ANSC_STATUS_SUCCESS == status);
}

BOOLEAN
AnscAsn1CRLIsCertRevoked
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSerialNumber
    )
{
    PANSC_ASN1_CRL                  pCRL        = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TBSCERTLIST          pTBSList;
    PANSC_ASN1_REVOKEDCERTIFICATES  pRevokedCerts;
    PANSC_ASN1_REVOKEDCERTIFICATE   pRevoked;
    ULONG                           i;
    PANSC_ASN1_INTEGER              pLookfor    = (PANSC_ASN1_INTEGER)hSerialNumber;
    PANSC_ASN1_INTEGER              pRevokedNumber;

    if( pCRL == NULL || pLookfor == NULL)
    {
        return FALSE;
    }

    pTBSList = (PANSC_ASN1_TBSCERTLIST)pCRL->GetTbsCertList(pCRL);

    if( pTBSList == NULL)
    {
        return FALSE;
    }

    pRevokedCerts = (PANSC_ASN1_REVOKEDCERTIFICATES)
        pTBSList->GetChildByIndex(pTBSList,5);

    if( pRevokedCerts == NULL)
    {
        return FALSE;
    }

    for( i = 0; i < pRevokedCerts->GetChildCount(pRevokedCerts); i ++)
    {
        pRevoked = (PANSC_ASN1_REVOKEDCERTIFICATE)
            pRevokedCerts->GetChildByIndex(pRevokedCerts, i);

        if( pRevoked != NULL)
        {
            pRevokedNumber = (PANSC_ASN1_INTEGER)pRevoked->GetChildByIndex(pRevoked,0);

            if( pLookfor->EqualsTo(pLookfor, pRevokedNumber, TRUE))
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOLEAN
AnscAsn1CRLEnumRevokedCert
    (
        ANSC_HANDLE                 hThisObject,
        EnumRevokedCertProc         proc,
        PVOID                       pData
    )
{
    PANSC_ASN1_CRL                  pCRL        = (PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TBSCERTLIST          pTBSList;
    PANSC_ASN1_REVOKEDCERTIFICATES  pRevokedCerts;
    PANSC_ASN1_REVOKEDCERTIFICATE   pRevoked;
    ULONG                           i;

    if( pCRL == NULL || proc == NULL)
    {
        return FALSE;
    }

    pTBSList = (PANSC_ASN1_TBSCERTLIST)pCRL->GetTbsCertList(pCRL);

    if( pTBSList == NULL)
    {
        return FALSE;
    }

    pRevokedCerts = (PANSC_ASN1_REVOKEDCERTIFICATES)
        pTBSList->GetChildByIndex(pTBSList,5);

    if( pRevokedCerts == NULL)
    {
        return FALSE;
    }

    for( i = 0; i < pRevokedCerts->GetChildCount(pRevokedCerts); i ++)
    {
        pRevoked = (PANSC_ASN1_REVOKEDCERTIFICATE)
            pRevokedCerts->GetChildByIndex(pRevokedCerts, i);

        if( pRevoked != NULL)
        {
            if( !proc
                    (
                        pData, 
                        pRevoked, 
                        pRevoked->GetChildByIndex(pRevoked,0),
                        pRevoked->GetChildByIndex(pRevoked,1)
                    )
              )
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

SIGNATURE_TYPE
AnscAsn1CRLGetSignatureType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pThisObject     =(PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER
                                    pSignature;
    CHAR                            pOIDString[128] = { 0 };

    if( pThisObject == NULL)
    {
        return SIGNATURE_RESERVED;
    }

    pSignature = (PANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER)
        pThisObject->GetSigatureAlgorithm(pThisObject);

    if( pSignature == NULL)
    {
        return SIGNATURE_RESERVED;
    }

    pSignature->GetAlgorOIDStringValue(pSignature, pOIDString);

    return PKIOIDStringToSignatureType(pOIDString);
}

BOOLEAN
AnscAsn1CRLIsCRLExpired
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PANSC_ASN1_CRL                  pThisObject     =(PANSC_ASN1_CRL)hThisObject;
    PANSC_ASN1_TIME                 pNextUpdate;
    PANSC_ASN1_ALTIME               pSelection;
    ANSC_UNIVERSAL_TIME             clockTime;

    if( pThisObject == NULL)
    {
        return FALSE;
    }

    pNextUpdate = (PANSC_ASN1_TIME)pThisObject->GetNextUpdateTime(pThisObject);

    if( pNextUpdate->bOptional)
    {
        return FALSE;
    }

    AnscAsn1GetCurrentTime((ANSC_HANDLE)&clockTime);

    pSelection = (PANSC_ASN1_ALTIME)pNextUpdate->hSelection;

    if( pSelection == NULL)
    {
        return FALSE;
    }

    if( pSelection->IsBefore
            (
                pSelection,
                clockTime.Year,
                clockTime.Month,
                clockTime.DayOfMonth,
                clockTime.Hour,
                clockTime.Minute,
                clockTime.Second
            ))
    {
         return TRUE;
    }

    return FALSE;
}

/**********************************************************************

 OBJECT -- ANSC_ASN1_TBSCERTLIST

 TBSCertList ::= Sequence 
     {
                           version Integer 
                         signature AlgorithmIdentifier 
                            issuer Name 
                        thisUpdate Time 
                        nextUpdate Time 
               revokedCertificates RevokedCertificates 
                     crlExtensions [CON 0] Extensions OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateTBSCertList
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_TBSCERTLIST          pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_TBSCERTLIST)
        AnscAsn1CreateSequence
            (
                (ANSC_HANDLE)sizeof(ANSC_ASN1_TBSCERTLIST)
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_TBSCERTLIST");
    pThisObject->SetName(pThisObject, "TBSCertList");

    pThisObject->Create             = AnscAsn1CreateTBSCertList;
    pThisObject->CreateChildAttr    = AnscAsn1TBSCertListCreateChildAttr;
    pThisObject->GetChildName       = AnscAsn1TBSCertListGetChildName;
    pThisObject->CreateChildObject  = AnscAsn1TBSCertListCreateChildObject;
    pThisObject->uTotalChild        = 7;

    /*
     * Create all the children
     */
    pThisObject->CreateAllChildren(pThisObject);


    return (ANSC_HANDLE)pThisObject;
}

ANSC_HANDLE
AnscAsn1TBSCertListCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    PANSC_ASN1_OBJECT               pThisObject      = NULL;
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    switch( index )
    {

        case 0:

            pThisObject = AnscAsn1CreateInteger(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
                pThisObject->bCanBeOptional = TRUE;
                pThisObject->bOptional = TRUE;
            }

            break;

        case 1:

            pThisObject = AnscAsn1CreateAlgorithmIdentifier(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 2:

            pThisObject = AnscAsn1CreateName(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 3:

            pThisObject = AnscAsn1CreateTime(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 4:

            pThisObject = AnscAsn1CreateTime(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
                pThisObject->bCanBeOptional = TRUE;
                pThisObject->bOptional = TRUE;
            }

            break;

        case 5:

            pThisObject = AnscAsn1CreateRevokedCertificates(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
                pThisObject->bCanBeOptional = TRUE;
                pThisObject->bOptional = TRUE;
            }

            break;

        case 6:

            pThisObject = AnscAsn1CreateExtensions(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
                pThisObject->bCanBeOptional = TRUE;
                pThisObject->bOptional = TRUE;
            }

            break;

    }

    return pThisObject;

}

PANSC_ATTR_OBJECT
AnscAsn1TBSCertListCreateChildAttr
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;

    switch ( index )
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:

                break;

        case 6:

                pAttrObject = (PANSC_ATTR_OBJECT)
                    AnscAsn1AttrCreate
                        (
                          CONTEXT_FORM,
                          0,
                          EXPLICIT_TYPE
                        );

                break;

    }

    return pAttrObject;

}

PCHAR
AnscAsn1TBSCertListGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{

    switch ( index )
    {
        case 0:

            return"version";

        case 1:

            return"signature";

        case 2:

            return"issuer";

        case 3:

            return"thisUpdate";

        case 4:

            return"nextUpdate";

        case 5:

            return"revokedCertificates";

        case 6:

            return"crlExtensions";

    }

    return "";

}


/**********************************************************************

 OBJECT -- ANSC_ASN1_REVOKEDCERTIFICATE

 RevokedCertificate ::= Sequence 
     {
             userCertificateNumber CertificateSerialNumber 
                    revocationDate Time 
                crlEntryExtensions Extensions 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevokedCertificate
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_REVOKEDCERTIFICATE   pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_REVOKEDCERTIFICATE)
        AnscAsn1CreateSequence
            (
                (ANSC_HANDLE)sizeof(ANSC_ASN1_REVOKEDCERTIFICATE)
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_REVOKEDCERTIFICATE");
    pThisObject->SetName(pThisObject, "RevokedCertificate");

    pThisObject->Create             = AnscAsn1CreateRevokedCertificate;
    pThisObject->GetChildName       = AnscAsn1RevokedCertificateGetChildName;
    pThisObject->CreateChildObject  = AnscAsn1RevokedCertificateCreateChildObject;
    pThisObject->uTotalChild        = 3;

    /*
     * Create all the children
     */
    pThisObject->CreateAllChildren(pThisObject);


    return (ANSC_HANDLE)pThisObject;
}

ANSC_HANDLE
AnscAsn1RevokedCertificateCreateChildObject
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    PANSC_ASN1_OBJECT               pThisObject      = NULL;
    PANSC_ASN1_SEQUENCE             pParent          = (PANSC_ASN1_SEQUENCE)hThisObject;

    switch( index )
    {

        case 0:

            pThisObject = AnscAsn1CreateCertificateSerialNumber(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 1:

            pThisObject = AnscAsn1CreateTime(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
            }

            break;

        case 2:

            pThisObject = AnscAsn1CreateExtensions(NULL);

            if( pThisObject != NULL)
            {
                pThisObject->AddAttribute(pThisObject, pParent->CreateChildAttr(pParent,index), FALSE);
                pThisObject->SetName(pThisObject, pParent->GetChildName(pParent,index));
                pThisObject->bCanBeOptional = TRUE;
                pThisObject->bOptional = TRUE;
            }

            break;

    }

    return pThisObject;

}

PCHAR
AnscAsn1RevokedCertificateGetChildName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       index
    )
{
    switch ( index )
    {
        case 0:

            return"userCertificateNumber";

        case 1:

            return"revocationDate";

        case 2:

            return"crlEntryExtensions";

    }

    return "";

}

/**********************************************************************

 OBJECT -- ANSC_ASN1_REVOKEDCERTIFICATES

 RevokedCertificates ::= SequenceOf RevokedCertificate  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateRevokedCertificates
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_REVOKEDCERTIFICATES  pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_REVOKEDCERTIFICATES)
        AnscAsn1CreateSequenceOf
            (
                hReserved
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_REVOKEDCERTIFICATES");
    pThisObject->SetName(pThisObject, "RevokedCertificates");

    pThisObject->Create             = AnscAsn1CreateRevokedCertificates;
    pThisObject->CreateChild        = AnscAsn1RevokedCertificatesCreateChild;
    pThisObject->IsChildValid       = AnscAsn1RevokedCertificatesIsChildValid;

    return (ANSC_HANDLE)pThisObject;
}

ANSC_HANDLE
AnscAsn1RevokedCertificatesCreateChild
    (
        ANSC_HANDLE                 hThisObject,
        BOOLEAN                     bAddItIn
    )
{
    PANSC_ASN1_SETOF                pParentObj   = (PANSC_ASN1_SETOF)hThisObject;
    PANSC_ASN1_OBJECT               pThisObject  = NULL;

    pThisObject  = AnscAsn1CreateRevokedCertificate(NULL);

    if( pThisObject != NULL && bAddItIn)
    {
        pParentObj->AddChild(pParentObj,pThisObject);
    }

    return pThisObject;
}

ANSC_STATUS
AnscAsn1RevokedCertificatesIsChildValid
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hChild
    )
{
    PANSC_ASN1_OBJECT               pChild    = (PANSC_ASN1_OBJECT)hChild;

    if( pChild == NULL)
    {
        return ANSC_ASN1_NULL_OBJCET;
    }

    if( pChild->ClassName == NULL || !AnscEqualString1(pChild->ClassName, "ANSC_ASN1_REVOKEDCERTIFICATE", TRUE))
    {
        return ANSC_ASN1_INVALID_TYPE_IN_SEQOF_OR_SETOF;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

 OBJECT -- ANSC_ASN1_SIGNATURE

 Signature ::= BitString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSignature
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_SIGNATURE            pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_SIGNATURE)
        AnscAsn1CreateBitString
            (
                hReserved
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_SIGNATURE");
    pThisObject->SetName(pThisObject, "Signature");

    pThisObject->Create             = AnscAsn1CreateSignature;

    return (ANSC_HANDLE)pThisObject;
}

/**********************************************************************

 OBJECT -- ANSC_ASN1_CERTIFICATELIST

 CertificateList ::= CRL 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCertificateList
    (
        ANSC_HANDLE                 hReserved
    )
{
    PANSC_ATTR_OBJECT               pAttrObject  = NULL;
    PANSC_ASN1_CERTIFICATELIST      pThisObject  = NULL;

    /*
     * Create the base ASN.1 object.
     */
    pThisObject = (PANSC_ASN1_CERTIFICATELIST)
        AnscAsn1CreateCRL
            (
                hReserved
            );

    if( pThisObject == NULL)
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for this ASN.1 object.
     */
    pThisObject->SetClassName(pThisObject, "ANSC_ASN1_CERTIFICATELIST");
    pThisObject->SetName(pThisObject, "CertificateList");

    pThisObject->Create             = AnscAsn1CreateCertificateList;

    return (ANSC_HANDLE)pThisObject;
}

