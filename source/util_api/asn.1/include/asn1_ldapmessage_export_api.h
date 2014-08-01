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

    MODULE: asn1_ldapmessage_export_api.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The Internal functions defined for ASN.1 objects

        *   ASN1_LDAPMESSAGE
        *   ASN1_LDAPPROTOCOL
        *   ASN1_CONTROLS
        *   ASN1_CONTROL
        *   ASN1_LDAPSTRING
        *   ASN1_MATCHINGRULEID
        *   ASN1_LDAPATTRDESCLIST
        *   ASN1_ATTRVALUEASSERTION
        *   ASN1_LDAPATTRSET
        *   ASN1_LDAPATTRIBUTE
        *   ASN1_LDAPRESULT
        *   ASN1_REFERRAL
        *   ASN1_BINDREQUEST
        *   ASN1_AUTHENTICATIONCHOICE
        *   ASN1_SASLCREDENTIALS
        *   ASN1_BINDRESPONSE
        *   ASN1_UNBINDREQUEST
        *   ASN1_SEARCHREQUEST
        *   ASN1_FILTER
        *   ASN1_FILTERS
        *   ASN1_SUBSTRINGFILTER
        *   ASN1_MATCHINGRULEASSERSIOIN
        *   ASN1_SUBSTRINGS
        *   ASN1_SUBSTRINGCHOICE
        *   ASN1_SEARCHRESULTENTRY
        *   ASN1_PARTIALATTRIBUTELIST
        *   ASN1_SEARCHRESULTREFERENCE
        *   ASN1_SEARCHRESULTDONE
        *   ASN1_MODIFYREQUEST
        *   ASN1_MODIFYRESPONSE
        *   ASN1_ADDREQUEST
        *   ASN1_LDAPATTRLIST
        *   ASN1_LDAPATTRTYPEANDVALUES
        *   ASN1_MODIFICATION
        *   ASN1_MODIFICATIONS
        *   ASN1_ADDRESPONSE
        *   ASN1_DELREQUEST
        *   ASN1_DELRESPONSE
        *   ASN1_MODIFYDNREQUESTS
        *   ASN1_MODIFYDNRESPONSE
        *   ASN1_COMPAREREQUEST
        *   ASN1_COMPARERESPONSE
        *   ASN1_ABANDONREQUEST
        *   ASN1_EXTENDEDREQUEST
        *   ASN1_EXTENDEDRESPONSE


    ---------------------------------------------------------------

    ENVIRONMENT:

        platform independent

    ---------------------------------------------------------------

    AUTHOR:

        ASNMAGIC ANSC CODE GENERATOR 1.0

    ---------------------------------------------------------------

    REVISION HISTORY:

        *   01/26/2006  initial revision

 **********************************************************************/


#ifndef  _ASN1_LDAPMESSAGE_EXPORTED_API_H
#define  _ASN1_LDAPMESSAGE_EXPORTED_API_H

/**********************************************************************

 OBJECT -- ASN1_LDAPMESSAGE

 LDAPMessage ::= Sequence 
     {
                         messageID Integer 
                        protocolOp LDAPProtocol 
                          controls [CON 0] IMP Controls 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPMessage
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPPROTOCOL

 LDAPProtocol ::= Choice 
     {
                       bindRequest BindRequest 
                      bindResponse BindResponse 
                     unbindRequest UnbindRequest 
                     searchRequest SearchRequest 
                    searchResEntry SearchResultEntry 
                     searchResDone SearchResultDone 
                      searchResRef SearchResultReference 
                     modifyRequest ModifyRequest 
                    modifyResponse ModifyResponse 
                        addRequest AddRequest 
                       addResponse AddResponse 
                        delRequest DelRequest 
                       delResponse DelResponse 
                      modDNRequest ModifyDNRequests 
                     modDNResponse ModifyDNResponse 
                    compareRequest CompareRequest 
                   compareResponse CompareResponse 
                    abandonRequest AbandonRequest 
                       extendedReq ExtendedRequest 
                      extendedResp ExtendedResponse 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPProtocol
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CONTROLS

 Controls ::= SequenceOf Control  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateControls
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_CONTROL

 Control ::= Sequence 
     {
                       controlType OctetString 
                       criticality BOOL DEF
                      controlValue OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateControl
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPSTRING

 LDAPString ::= OctetString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPString
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MATCHINGRULEID

 MatchingRuleId ::= LDAPString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateMatchingRuleId
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPATTRDESCLIST

 LDAPAttrDescList ::= SequenceOf OctetString  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPAttrDescList
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ATTRVALUEASSERTION

 AttrValueAssertion ::= Sequence 
     {
                     attributeDesc OctetString 
                    assertionValue OctetString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAttrValueAssertion
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPATTRSET

 LDAPAttrSet ::= SetOf OctetString  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPAttrSet
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPATTRIBUTE

 LDAPAttribute ::= Sequence 
     {
                          attrtype OctetString 
                              vals LDAPAttrSet 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPAttribute
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPRESULT

 LDAPResult ::= Sequence 
     {
                        resultCode Enumerate 
                         matchedDN OctetString 
                      errorMessage OctetString 
                          referral [CON 3] IMP Referral OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPResult
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_REFERRAL

 Referral ::= SequenceOf OctetString  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateReferral
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_BINDREQUEST

 BindRequest ::=[APP 0] IMP Sequence 
     {
                           version Integer 
                           reqname OctetString 
                        authchoice AuthenticationChoice 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateBindRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_AUTHENTICATIONCHOICE

 AuthenticationChoice ::= Choice 
     {
                            simple [CON 0] IMP OctetString 
                              sasl [CON 3] IMP SaslCredentials 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAuthenticationChoice
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SASLCREDENTIALS

 SaslCredentials ::= Sequence 
     {
                         mechanism OctetString 
                       credentials OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSaslCredentials
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_BINDRESPONSE

 BindResponse ::=[APP 1] IMP Sequence 
     {
                        resultCode Enumerate 
                         matchedDN LDAPString 
                      errorMessage LDAPString 
                          referral [CON 3] IMP Referral OPT
                   serverSaslCreds [CON 7] IMP OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateBindResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_UNBINDREQUEST

 UnbindRequest ::=[APP 2] IMP NULL 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateUnbindRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SEARCHREQUEST

 SearchRequest ::=[APP 3] IMP Sequence 
     {
                        baseobject OctetString 
                             scope Enumerate 
                        derefAlias Enumerate 
                         sizeLimit Integer 
                         timeLimit Integer 
                         typesOnly BOOL 
                            filter Filter 
                        attributes LDAPAttrDescList 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSearchRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_FILTER

 Filter ::= Choice 
     {
                               and [CON 0] IMP Filters 
                                or [CON 1] IMP Filters 
                               not [CON 2] IMP Filter 
                     equalityMatch [CON 3] IMP AttrValueAssertion 
                        substrings [CON 4] IMP SubstringFilter 
                      greatOrEqual [CON 5] IMP AttrValueAssertion 
                       lessOrEqual [CON 6] IMP AttrValueAssertion 
                           present [CON 7] IMP OctetString 
                       approxMatch [CON 8] IMP AttrValueAssertion 
                   extensibleMatch [CON 9] IMP MatchingRuleAssersioin 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateFilter
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_FILTERS

 Filters ::= SetOf Filter  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateFilters
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SUBSTRINGFILTER

 SubstringFilter ::= Sequence 
     {
                        filterType OctetString 
                        substrings Substrings 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSubstringFilter
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MATCHINGRULEASSERSIOIN

 MatchingRuleAssersioin ::= Sequence 
     {
                      matchingRule [CON 1] IMP MatchingRuleId OPT
                         matchType [CON 2] IMP OctetString OPT
                        matchValue [CON 3] IMP OctetString 
                           dnAttrs [CON 4] IMP BOOL DEF
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateMatchingRuleAssersioin
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SUBSTRINGS

 Substrings ::= SequenceOf SubstringChoice  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSubstrings
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SUBSTRINGCHOICE

 SubstringChoice ::= Choice 
     {
                          initials [CON 0] IMP LDAPString 
                               any [CON 1] IMP LDAPString 
                             final [CON 2] IMP LDAPString 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSubstringChoice
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SEARCHRESULTENTRY

 SearchResultEntry ::=[APP 4] IMP Sequence 
     {
                        objectName OctetString 
                              attr PartialAttributeList 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSearchResultEntry
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_PARTIALATTRIBUTELIST

 PartialAttributeList ::= SequenceOf LDAPAttribute  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreatePartialAttributeList
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SEARCHRESULTREFERENCE

 SearchResultReference ::=[APP 19] IMP SequenceOf OctetString  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSearchResultReference
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_SEARCHRESULTDONE

 SearchResultDone ::=[APP 5] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateSearchResultDone
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFYREQUEST

 ModifyRequest ::=[APP 6] IMP Sequence 
     {
                            object OctetString 
                     modifications Modifications 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModifyRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFYRESPONSE

 ModifyResponse ::=[APP 7] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModifyResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ADDREQUEST

 AddRequest ::=[APP 8] IMP Sequence 
     {
                             entry OctetString 
                          attrlist LDAPAttrList 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAddRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPATTRLIST

 LDAPAttrList ::= SequenceOf LDAPAttribute  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPAttrList
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_LDAPATTRTYPEANDVALUES

 LDAPAttrTypeAndValues ::= Sequence 
     {
                          attrType OctetString 
                              vals LDAPAttrSet 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateLDAPAttrTypeAndValues
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFICATION

 Modification ::= Sequence 
     {
                         operation Enumerate 
                     typeAndValues LDAPAttrTypeAndValues 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModification
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFICATIONS

 Modifications ::= SequenceOf Modification  {}

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModifications
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ADDRESPONSE

 AddResponse ::=[APP 9] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAddResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_DELREQUEST

 DelRequest ::=[APP 10] IMP OctetString 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateDelRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_DELRESPONSE

 DelResponse ::=[APP 11] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateDelResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFYDNREQUESTS

 ModifyDNRequests ::=[APP 12] IMP Sequence 
     {
                             entry OctetString 
                            newrdn OctetString 
                       deleteOldDn BOOL 
                       newSuperior [CON 0] IMP OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModifyDNRequests
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_MODIFYDNRESPONSE

 ModifyDNResponse ::=[APP 13] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateModifyDNResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_COMPAREREQUEST

 CompareRequest ::=[APP 14] IMP Sequence 
     {
                             entry OctetString 
                               ava AttrValueAssertion 
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCompareRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_COMPARERESPONSE

 CompareResponse ::=[APP 15] IMP LDAPResult 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateCompareResponse
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_ABANDONREQUEST

 AbandonRequest ::=[APP 16] IMP Integer 

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateAbandonRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_EXTENDEDREQUEST

 ExtendedRequest ::=[APP 23] IMP Sequence 
     {
                       requestName [CON 0] IMP OctetString 
                      requestValue [CON 1] IMP OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateExtendedRequest
    (
        ANSC_HANDLE                 hReserved
    );

/**********************************************************************

 OBJECT -- ASN1_EXTENDEDRESPONSE

 ExtendedResponse ::=[APP 24] IMP Sequence 
     {
                        resultCode Enumerate 
                         matchedDN LDAPString 
                      errorMessage LDAPString 
                          referral [CON 3] IMP Referral OPT
                      responsename [CON 10] IMP OctetString OPT
                          response [CON 11] IMP OctetString OPT
     }

 **********************************************************************/

ANSC_HANDLE 
AnscAsn1CreateExtendedResponse
    (
        ANSC_HANDLE                 hReserved
    );


#endif  /* _ASN1_LDAPMESSAGE_EXPORTED_API_H */
