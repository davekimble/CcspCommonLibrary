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

    MODULE: ansc_asn1_Name_interface.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The ASN.1 object defined in this file

        *   ANSC_ASN1_NAME
        *   ANSC_ASN1_RDNSEQUENCE
        *   ANSC_ASN1_ATTRIBUTE
        *   ANSC_ASN1_RELATIVEDISTINGUISHEDNAME
        *   ANSC_ASN1_ATTRIBUTETYPEANDVALUE
        *   ANSC_ASN1_ATTRIBUTEVALUES
        *   ANSC_ASN1_ATTRIBUTEVALUE
        *   ANSC_ASN1_X520NAME
        *   ANSC_ASN1_UNSTRUCTUREDNAME
        *   ANSC_ASN1_DIRECTORYSTRING
        *   ANSC_ASN1_MESSAGEDIGEST
        *   ANSC_ASN1_SIGNINGTIME
        *   ANSC_ASN1_CHLLENGEPASSWORD
        *   ANSC_ASN1_UNSTRUCTUREDADDRESS
        *   ANSC_ASN1_CONTENTTYPE
        *   ANSC_ASN1_X520COMMONNAME
        *   ANSC_ASN1_X520LOCALITYNAME


    ---------------------------------------------------------------

    ENVIRONMENT:

        platform independent

    ---------------------------------------------------------------

    AUTHOR:

        ASNMAGIC ANSC CODE GENERATOR 1.0

    ---------------------------------------------------------------

    REVISION HISTORY:

        *   05/07/2002  initial revision
        *   09/05/2002  GetCommonName() was added in Name object;

 **********************************************************************/


#ifndef  _ANSC_ASN1_NAME_INTERFACE_H
#define  _ANSC_ASN1_NAME_INTERFACE_H

/**********************************************************************

 OBJECT -- ANSC_ASN1_NAME

 Name ::= Choice 
     {
                       rdnSequence RDNSequence 
     }

 **********************************************************************/
typedef BOOLEAN
(*PFN_NAME_INIT_ATTR)
    (
        ANSC_HANDLE                 hThisObject,
        PALCERTIFICATE_ATTRIBUTE    pAttrObject
    );

typedef BOOLEAN
(*PFN_NAME_ADD_ATTR)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pOIDString,
        ANSC_HANDLE                 hValueHandle
    );

typedef BOOLEAN
(*PFN_NAME_EXPORT)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pString,
        PULONG                      pLength
    );

typedef BOOLEAN
(*PFN_NAME_GETVALUE_BYOID)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pOIDString,
        PCHAR                       pString,
        PULONG                      pLength
    );

typedef BOOLEAN
(*PFN_NAME_ISEMPTY)
    (
        ANSC_HANDLE                 hThisObject
    );

#define  NAME_MASK_RDNSEQUENCE                                     0x00
#define  NAME_MAXI_MASK                                            0x00

#define  ANSC_ASN1_NAME_CLASS_CONTENT                                 \
    /* duplication of the base object class content */                \
    ANSC_ASN1_CHOICE_CLASS_CONTENT                                    \
    /* start of object class content */                               \
    PFN_NAME_INIT_ATTR              InitAttribute;                    \
    PFN_NAME_ADD_ATTR               AddRDNAttribute;                  \
    PFN_NAME_EXPORT                 ExportToString;                   \
    PFN_NAME_EXPORT                 GetCommonName;                    \
    PFN_NAME_GETVALUE_BYOID         GetNameByOID;                     \
    PFN_NAME_ISEMPTY                IsNameEmpty;                      \
    /* end of object class content */                                 \


typedef  struct
_ANSC_ASN1_NAME
{
    ANSC_ASN1_NAME_CLASS_CONTENT
}
ANSC_ASN1_NAME,  *PANSC_ASN1_NAME;

#define  ACCESS_ANSC_ASN1_NAME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_NAME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_RDNSEQUENCE

 RDNSequence ::= SequenceOf RelativeDistinguishedName  {}

 **********************************************************************/

typedef  ANSC_ASN1_SEQUENCEOF ANSC_ASN1_RDNSEQUENCE, *PANSC_ASN1_RDNSEQUENCE;

#define  ACCESS_ANSC_ASN1_RDNSEQUENCE(p)    ACCESS_CONTAINER(p, ANSC_ASN1_RDNSEQUENCE, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_ATTRIBUTE

 Attribute ::= Sequence 
     {
                     attributeType OID 
                             value AttributeValues 
     }

 **********************************************************************/
typedef BOOLEAN
(*PFN_ATTR_SET_TYPE_AND_STRVALUE)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pOIDString,
        PCHAR                       pValue,
        ULONG                       ulOfValue
    );

typedef BOOLEAN
(*PFN_ATTR_SET_TYPE_AND_HANDLE)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pOIDString,
        ANSC_HANDLE                 hValue
    );


#define  ANSC_ASN1_ATTRIBUTE_CLASS_CONTENT                            \
    /* duplication of the base object class content */                \
    ANSC_ASN1_SEQUENCE_CLASS_CONTENT                                  \
    /* start of object class content */                               \
    PFN_ATTR_SET_TYPE_AND_STRVALUE  SetTypeAndStringValue;            \
    PFN_ATTR_SET_TYPE_AND_HANDLE    SetTypeAndHandle;                 \
    /* end of object class content */                                 \


typedef  struct
_ANSC_ASN1_ATTRIBUTE
{
    ANSC_ASN1_ATTRIBUTE_CLASS_CONTENT
}
ANSC_ASN1_ATTRIBUTE,  *PANSC_ASN1_ATTRIBUTE;

#define  ACCESS_ANSC_ASN1_ATTRIBUTE(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_ATTRIBUTE, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_RELATIVEDISTINGUISHEDNAME

 RelativeDistinguishedName ::= SetOf AttributeTypeAndValue  {}

 **********************************************************************/

typedef  ANSC_ASN1_SETOF ANSC_ASN1_RELATIVEDISTINGUISHEDNAME, *PANSC_ASN1_RELATIVEDISTINGUISHEDNAME;

#define  ACCESS_ANSC_ASN1_RELATIVEDISTINGUISHEDNAME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_RELATIVEDISTINGUISHEDNAME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_ATTRIBUTETYPEANDVALUE

 AttributeTypeAndValue ::= Sequence 
     {
                     attributeType OID 
                             value AttributeValue 
     }

 **********************************************************************/
typedef BOOLEAN
(*PFN_TYPEANDVALUE_EXPORT)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pString,
        PULONG                      pLength
    );

#define  ANSC_ASN1_ATTRIBUTETYPEANDVALUE_CLASS_CONTENT                \
    /* duplication of the base object class content */                \
    ANSC_ASN1_SEQUENCE_CLASS_CONTENT                                  \
    /* start of object class content */                               \
    PFN_ATTR_SET_TYPE_AND_STRVALUE  SetTypeAndStringValue;            \
    PFN_ATTR_SET_TYPE_AND_HANDLE    SetTypeAndHandle;                 \
    PFN_TYPEANDVALUE_EXPORT         ExportToString;                   \
    /* end of object class content */                                 \

typedef  struct
_ANSC_ASN1_ATTRIBUTETYPEANDVALUE
{
    ANSC_ASN1_ATTRIBUTETYPEANDVALUE_CLASS_CONTENT
}
ANSC_ASN1_ATTRIBUTETYPEANDVALUE,  *PANSC_ASN1_ATTRIBUTETYPEANDVALUE;

#define  ACCESS_ANSC_ASN1_ATTRIBUTETYPEANDVALUE(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_ATTRIBUTETYPEANDVALUE, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_ATTRIBUTEVALUES

 AttributeValues ::= SetOf AttributeValue  {}

 **********************************************************************/

typedef  ANSC_ASN1_SETOF ANSC_ASN1_ATTRIBUTEVALUES, *PANSC_ASN1_ATTRIBUTEVALUES;

#define  ACCESS_ANSC_ASN1_ATTRIBUTEVALUES(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_ATTRIBUTEVALUES, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_ATTRIBUTEVALUE

 AttributeValue ::= Choice 
     {
                   x520dnQualifier PrintableString 
                       countryName PrintableString 
                 pkcs9EmailAddress IA5String 
                       contentType ContentType 
                  unstructuredName UnstructuredName 
                     messageDigest MessageDigest 
                       signingTime SigningTime 
                 challengePassword ChllengePassword 
               unstructuredAddress UnstructuredAddress 
                         bmpString BMPString 
                          x520Name X520name 
                    x520CommonName X520CommonName 
                        signerInfo SignerInfo 
                   pkcs9LocalKeyID OctetString 
                          keyUsage BitString 
                        utf8String UTF8String 
                      genderString PrintableString 
              printableCountryName PrintableString 
                      localityName X520LocalityName 
                   domainComponent DirectoryString 
                         t61String TeletexString 
                        extensions Extensions 
                     streetAddress DirectoryString 
     }

 **********************************************************************/

#define  ATTRIBUTEVALUE_MASK_X520DNQUALIFIER                       0x00
#define  ATTRIBUTEVALUE_MASK_COUNTRYNAME                           0x01
#define  ATTRIBUTEVALUE_MASK_PKCS9EMAILADDRESS                     0x02
#define  ATTRIBUTEVALUE_MASK_CONTENTTYPE                           0x03
#define  ATTRIBUTEVALUE_MASK_UNSTRUCTUREDNAME                      0x04
#define  ATTRIBUTEVALUE_MASK_MESSAGEDIGEST                         0x05
#define  ATTRIBUTEVALUE_MASK_SIGNINGTIME                           0x06
#define  ATTRIBUTEVALUE_MASK_CHALLENGEPASSWORD                     0x07
#define  ATTRIBUTEVALUE_MASK_UNSTRUCTUREDADDRESS                   0x08
#define  ATTRIBUTEVALUE_MASK_BMPSTRING                             0x09
#define  ATTRIBUTEVALUE_MASK_X520NAME                              0x0A
#define  ATTRIBUTEVALUE_MASK_X520COMMONNAME                        0x0B
#define  ATTRIBUTEVALUE_MASK_SIGNERINFO                            0x0C
#define  ATTRIBUTEVALUE_MASK_PKCS9LOCALKEYID                       0x0D
#define  ATTRIBUTEVALUE_MASK_KEYUSAGE                              0x0E
#define  ATTRIBUTEVALUE_MASK_UTF8STRING                            0x0F
#define  ATTRIBUTEVALUE_MASK_GENDERSTRING                          0x10
#define  ATTRIBUTEVALUE_MASK_PRINTABLECOUNTRYNAME                  0x11
#define  ATTRIBUTEVALUE_MASK_LOCALITYNAME                          0x12
#define  ATTRIBUTEVALUE_MASK_DOMAINCOMPONENT                       0x13
#define  ATTRIBUTEVALUE_MASK_T61STRING                             0x14
#define  ATTRIBUTEVALUE_MASK_EXTENSIONS                            0x15
#define  ATTRIBUTEVALUE_MASK_STREETADDRESS                         0x16
#define  ATTRIBUTEVALUE_MAXI_MASK                                  0x16

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_ATTRIBUTEVALUE, *PANSC_ASN1_ATTRIBUTEVALUE;

#define  ACCESS_ANSC_ASN1_ATTRIBUTEVALUE(p)  ACCESS_CONTAINER(p, ANSC_ASN1_ATTRIBUTEVALUE, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_X520NAME

 X520name ::= Choice 
     {
                     teletexString TeletexString 
                   printableString PrintableString 
                   universalString UniversalString 
                        utf8String UTF8String 
                         bmpString BMPString 
                       octetString OctetString 
     }

 **********************************************************************/

#define  X520NAME_MASK_TELETEXSTRING                               0x00
#define  X520NAME_MASK_PRINTABLESTRING                             0x01
#define  X520NAME_MASK_UNIVERSALSTRING                             0x02
#define  X520NAME_MASK_UTF8STRING                                  0x03
#define  X520NAME_MASK_BMPSTRING                                   0x04
#define  X520NAME_MASK_OCTETSTRING                                 0x05
#define  X520NAME_MAXI_MASK                                        0x05

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_X520NAME, *PANSC_ASN1_X520NAME;

#define  ACCESS_ANSC_ASN1_X520NAME(p)    ACCESS_CONTAINER(p, ANSC_ASN1_X520NAME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_UNSTRUCTUREDNAME

 UnstructuredName ::= Choice 
     {
                         iA5String IA5String 
                   universalString UniversalString 
                   printableString PrintableString 
     }

 **********************************************************************/

#define  UNSTRUCTUREDNAME_MASK_IA5STRING                           0x00
#define  UNSTRUCTUREDNAME_MASK_UNIVERSALSTRING                     0x01
#define  UNSTRUCTUREDNAME_MASK_PRINTABLESTRING                     0x02
#define  UNSTRUCTUREDNAME_MAXI_MASK                                0x02

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_UNSTRUCTUREDNAME, *PANSC_ASN1_UNSTRUCTUREDNAME;

#define  ACCESS_ANSC_ASN1_UNSTRUCTUREDNAME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_UNSTRUCTUREDNAME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DIRECTORYSTRING

 DirectoryString ::= Choice 
     {
                     teletexString TeletexString 
                   printableString PrintableString 
                   universalString UniversalString 
                        utf8String UTF8String 
                         bmpString BMPString 
     }

 **********************************************************************/

#define  DIRECTORYSTRING_MASK_TELETEXSTRING                        0x00
#define  DIRECTORYSTRING_MASK_PRINTABLESTRING                      0x01
#define  DIRECTORYSTRING_MASK_UNIVERSALSTRING                      0x02
#define  DIRECTORYSTRING_MASK_UTF8STRING                           0x03
#define  DIRECTORYSTRING_MASK_BMPSTRING                            0x04
#define  DIRECTORYSTRING_MAXI_MASK                                 0x04

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_DIRECTORYSTRING, *PANSC_ASN1_DIRECTORYSTRING;

#define  ACCESS_ANSC_ASN1_DIRECTORYSTRING(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DIRECTORYSTRING, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_MESSAGEDIGEST

 MessageDigest ::= OctetString 

 **********************************************************************/

typedef  ANSC_ASN1_OCTETSTRING ANSC_ASN1_MESSAGEDIGEST, *PANSC_ASN1_MESSAGEDIGEST;

#define  ACCESS_ANSC_ASN1_MESSAGEDIGEST(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_MESSAGEDIGEST, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_SIGNINGTIME

 SigningTime ::= Time 

 **********************************************************************/

typedef  ANSC_ASN1_TIME ANSC_ASN1_SIGNINGTIME, *PANSC_ASN1_SIGNINGTIME;

#define  ACCESS_ANSC_ASN1_SIGNINGTIME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_SIGNINGTIME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_CHLLENGEPASSWORD

 ChllengePassword ::= Choice 
     {
                   printableString PrintableString 
                         t61String TeletexString 
                   universalString UniversalString 
     }

 **********************************************************************/

#define  CHLLENGEPASSWORD_MASK_PRINTABLESTRING                     0x00
#define  CHLLENGEPASSWORD_MASK_T61STRING                           0x01
#define  CHLLENGEPASSWORD_MASK_UNIVERSALSTRING                     0x02
#define  CHLLENGEPASSWORD_MAXI_MASK                                0x02

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_CHLLENGEPASSWORD, *PANSC_ASN1_CHLLENGEPASSWORD;

#define  ACCESS_ANSC_ASN1_CHLLENGEPASSWORD(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_CHLLENGEPASSWORD, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_UNSTRUCTUREDADDRESS

 UnstructuredAddress ::= Choice 
     {
                   printableString PrintableString 
                         t61String TeletexString 
                   universalString UniversalString 
     }

 **********************************************************************/

#define  UNSTRUCTUREDADDRESS_MASK_PRINTABLESTRING                  0x00
#define  UNSTRUCTUREDADDRESS_MASK_T61STRING                        0x01
#define  UNSTRUCTUREDADDRESS_MASK_UNIVERSALSTRING                  0x02
#define  UNSTRUCTUREDADDRESS_MAXI_MASK                             0x02

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_UNSTRUCTUREDADDRESS,    \
         *PANSC_ASN1_UNSTRUCTUREDADDRESS;

#define  ACCESS_ANSC_ASN1_UNSTRUCTUREDADDRESS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_UNSTRUCTUREDADDRESS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_CONTENTTYPE

 ContentType ::= OID 

 **********************************************************************/

typedef  ANSC_ASN1_OIDEN ANSC_ASN1_CONTENTTYPE,    \
         *PANSC_ASN1_CONTENTTYPE;

#define  ACCESS_ANSC_ASN1_CONTENTTYPE(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_CONTENTTYPE, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_X520COMMONNAME

 X520CommonName ::= Choice 
     {
                     teletexString TeletexString 
                   printableString PrintableString 
                   universalString UniversalString 
                        utf8String UTF8String 
                         bmpString BMPString 
     }

 **********************************************************************/

#define  X520COMMONNAME_MASK_TELETEXSTRING                         0x00
#define  X520COMMONNAME_MASK_PRINTABLESTRING                       0x01
#define  X520COMMONNAME_MASK_UNIVERSALSTRING                       0x02
#define  X520COMMONNAME_MASK_UTF8STRING                            0x03
#define  X520COMMONNAME_MASK_BMPSTRING                             0x04
#define  X520COMMONNAME_MAXI_MASK                                  0x04

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_X520COMMONNAME,    \
         *PANSC_ASN1_X520COMMONNAME;

#define  ACCESS_ANSC_ASN1_X520COMMONNAME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_X520COMMONNAME, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_X520LOCALITYNAME

 X520LocalityName ::= Choice 
     {
                     teletexString TeletexString 
                   printableString PrintableString 
                   universalString UniversalString 
                        utf8String UTF8String 
                         bmpString BMPString 
     }

 **********************************************************************/

#define  X520LOCALITYNAME_MASK_TELETEXSTRING                       0x00
#define  X520LOCALITYNAME_MASK_PRINTABLESTRING                     0x01
#define  X520LOCALITYNAME_MASK_UNIVERSALSTRING                     0x02
#define  X520LOCALITYNAME_MASK_UTF8STRING                          0x03
#define  X520LOCALITYNAME_MASK_BMPSTRING                           0x04
#define  X520LOCALITYNAME_MAXI_MASK                                0x04

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_X520LOCALITYNAME,    \
         *PANSC_ASN1_X520LOCALITYNAME;

#define  ACCESS_ANSC_ASN1_X520LOCALITYNAME(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_X520LOCALITYNAME, Linkage)


#endif  /*_ANSC_ASN1_NAME_INTERFACE_H*/

