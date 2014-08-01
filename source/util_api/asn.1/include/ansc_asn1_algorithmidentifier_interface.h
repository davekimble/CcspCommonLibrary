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

    MODULE: ansc_asn1_AlgorithmIdentifier_interface.h

        ASN.1 ANSC Code Generated by Cisco Systems, Inc.

    ---------------------------------------------------------------

    COPYRIGHT:

        Cisco Systems, Inc., 1999 ~ 2003

        All Rights Reserved.

    ---------------------------------------------------------------

    DESCRIPTION:

        The ASN.1 object defined in this file

        *   ANSC_ASN1_ALGORITHMIDENTIFIER
        *   ANSC_ASN1_PARAMETERS
        *   ANSC_ASN1_DSS_PARMS
        *   ANSC_ASN1_DOMAINPARAMETERS
        *   ANSC_ASN1_VALIDATIONPARMS
        *   ANSC_ASN1_PBMPARAMETER
        *   ANSC_ASN1_DHBMPARAMETER
        *   ANSC_ASN1_CASE5MACPARAMETER
        *   ANSC_ASN1_PKCS12PBEPARAMS
        *   ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER
        *   ANSC_ASN1_SIGNATUREPARAMETERS
        *   ANSC_ASN1_DIGESTALGORITHMIDENTIFIER
        *   ANSC_ASN1_DHKEYAGREEMENT

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


#ifndef  _ANSC_ASN1_ALGORITHMIDENTIFIER_INTERFACE_H
#define  _ANSC_ASN1_ALGORITHMIDENTIFIER_INTERFACE_H

/**********************************************************************

 OBJECT -- ANSC_ASN1_ALGORITHMIDENTIFIER

 AlgorithmIdentifier ::= Sequence 
     {
                      algorithmOID OID 
                        parameters Parameters OPT
     }

 **********************************************************************/
typedef  BOOLEAN
(*PFN_ALGORITHM_FUN)
    (
        ANSC_HANDLE                 hThisObject,
        PCHAR                       pStringValue
    );

#define  ANSC_ASN1_ALGORITHMIDENTIFIER_CLASS_CONTENT                  \
    /* duplication of the base object class content */                \
    ANSC_ASN1_SEQUENCE_CLASS_CONTENT                                  \
    /* start of object class content */                               \
    PFN_ALGORITHM_FUN               GetAlgorOIDStringValue;           \
    PFN_ALGORITHM_FUN               SetAlgorOIDStringValue;           \
    /* end of object class content */                                 \


typedef  struct
_ANSC_ASN1_ALGORITHMIDENTIFIER
{
    ANSC_ASN1_ALGORITHMIDENTIFIER_CLASS_CONTENT
}
ANSC_ASN1_ALGORITHMIDENTIFIER,  *PANSC_ASN1_ALGORITHMIDENTIFIER;

#define  ACCESS_ANSC_ASN1_ALGORITHMIDENTIFIER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_ALGORITHMIDENTIFIER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_PARAMETERS

 Parameters ::= Choice 
     {
                         nullParms NULL 
                          dssParms Dss_Parms 
                       octetString OctetString 
                  domainParameters DomainParameters 
                      pbmParameter PBMParameter 
                     dhbmParameter DHBMParameter 
                 case5MacParameter Case5MacParameter 
                   pkcs12PbeParams PKCS12PbeParams 
                    dhKeyAgreement DHKeyAgreement 
     }

 **********************************************************************/

#define  PARAMETERS_MASK_NULLPARMS                                 0x00
#define  PARAMETERS_MASK_DSSPARMS                                  0x01
#define  PARAMETERS_MASK_OCTETSTRING                               0x02
#define  PARAMETERS_MASK_DOMAINPARAMETERS                          0x03
#define  PARAMETERS_MASK_PBMPARAMETER                              0x04
#define  PARAMETERS_MASK_DHBMPARAMETER                             0x05
#define  PARAMETERS_MASK_CASE5MACPARAMETER                         0x06
#define  PARAMETERS_MASK_PKCS12PBEPARAMS                           0x07
#define  PARAMETERS_MASK_DHKEYAGREEMENT                            0x08
#define  PARAMETERS_MAXI_MASK                                      0x08

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_PARAMETERS, *PANSC_ASN1_PARAMETERS;

#define  ACCESS_ANSC_ASN1_PARAMETERS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_PARAMETERS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DSS_PARMS

 Dss_Parms ::= Sequence 
     {
                                 p Integer 
                                 q Integer 
                                 g Integer 
     }

 **********************************************************************/

#define  ANSC_ASN1_DSS_PARMS_CLASS_CONTENT              ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_DSS_PARMS
{
    ANSC_ASN1_DSS_PARMS_CLASS_CONTENT
}
ANSC_ASN1_DSS_PARMS,  *PANSC_ASN1_DSS_PARMS;

#define  ACCESS_ANSC_ASN1_DSS_PARMS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DSS_PARMS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DOMAINPARAMETERS

 DomainParameters ::= Sequence 
     {
                                 p Integer 
                                 g Integer 
                                 q Integer 
                                 j Integer 
                   validationParms ValidationParms 
     }

 **********************************************************************/

#define  ANSC_ASN1_DOMAINPARAMETERS_CLASS_CONTENT       ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_DOMAINPARAMETERS
{
    ANSC_ASN1_DOMAINPARAMETERS_CLASS_CONTENT
}
ANSC_ASN1_DOMAINPARAMETERS,  *PANSC_ASN1_DOMAINPARAMETERS;

#define  ACCESS_ANSC_ASN1_DOMAINPARAMETERS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DOMAINPARAMETERS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_VALIDATIONPARMS

 ValidationParms ::= Sequence 
     {
                              seed BitString 
                       pgenCounter Integer 
     }

 **********************************************************************/

#define  ANSC_ASN1_VALIDATIONPARMS_CLASS_CONTENT        ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_VALIDATIONPARMS
{
    ANSC_ASN1_VALIDATIONPARMS_CLASS_CONTENT
}
ANSC_ASN1_VALIDATIONPARMS,  *PANSC_ASN1_VALIDATIONPARMS;

#define  ACCESS_ANSC_ASN1_VALIDATIONPARMS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_VALIDATIONPARMS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_PBMPARAMETER

 PBMParameter ::= Sequence 
     {
                              salt OctetString 
                               owf AlgorithmIdentifier 
                    iterationCount Integer 
                               mac AlgorithmIdentifier 
     }

 **********************************************************************/

#define  ANSC_ASN1_PBMPARAMETER_CLASS_CONTENT           ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_PBMPARAMETER
{
    ANSC_ASN1_PBMPARAMETER_CLASS_CONTENT
}
ANSC_ASN1_PBMPARAMETER,  *PANSC_ASN1_PBMPARAMETER;

#define  ACCESS_ANSC_ASN1_PBMPARAMETER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_PBMPARAMETER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DHBMPARAMETER

 DHBMParameter ::= Sequence 
     {
                               owf AlgorithmIdentifier 
                               mac AlgorithmIdentifier 
     }

 **********************************************************************/

#define  ANSC_ASN1_DHBMPARAMETER_CLASS_CONTENT          ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_DHBMPARAMETER
{
    ANSC_ASN1_DHBMPARAMETER_CLASS_CONTENT
}
ANSC_ASN1_DHBMPARAMETER,  *PANSC_ASN1_DHBMPARAMETER;

#define  ACCESS_ANSC_ASN1_DHBMPARAMETER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DHBMPARAMETER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_CASE5MACPARAMETER

 Case5MacParameter ::= Sequence 
     {
                         macLength Integer 
                         keyLength Integer 
     }

 **********************************************************************/

#define  ANSC_ASN1_CASE5MACPARAMETER_CLASS_CONTENT      ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_CASE5MACPARAMETER
{
    ANSC_ASN1_CASE5MACPARAMETER_CLASS_CONTENT
}
ANSC_ASN1_CASE5MACPARAMETER,  *PANSC_ASN1_CASE5MACPARAMETER;

#define  ACCESS_ANSC_ASN1_CASE5MACPARAMETER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_CASE5MACPARAMETER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_PKCS12PBEPARAMS

 PKCS12PbeParams ::= Sequence 
     {
                              salt OctetString 
                        iterations Integer 
     }

 **********************************************************************/

#define  ANSC_ASN1_PKCS12PBEPARAMS_CLASS_CONTENT        ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_PKCS12PBEPARAMS
{
    ANSC_ASN1_PKCS12PBEPARAMS_CLASS_CONTENT
}
ANSC_ASN1_PKCS12PBEPARAMS,  *PANSC_ASN1_PKCS12PBEPARAMS;

#define  ACCESS_ANSC_ASN1_PKCS12PBEPARAMS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_PKCS12PBEPARAMS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER

 SignatureAlgorithmIdentifier ::= Sequence 
     {
                      algorithmOID OID 
               signatureParameters SignatureParameters 
     }

 **********************************************************************/

#define  ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER_CLASS_CONTENT         \
    /* duplication of the base object class content */                \
    ANSC_ASN1_SEQUENCE_CLASS_CONTENT                                  \
    /* start of object class content */                               \
    PFN_ALGORITHM_FUN               GetAlgorOIDStringValue;           \
    PFN_ALGORITHM_FUN               SetAlgorOIDStringValue;           \
    /* end of object class content */                                 \

typedef  struct
_ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER
{
    ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER_CLASS_CONTENT
}
ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER,  *PANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER;

#define  ACCESS_ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_SIGNATUREALGORITHMIDENTIFIER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_SIGNATUREPARAMETERS

 SignatureParameters ::= Choice 
     {
                         nullParms NULL 
     }

 **********************************************************************/

#define  SIGNATUREPARAMETERS_MASK_NULLPARMS                        0x00
#define  SIGNATUREPARAMETERS_MAXI_MASK                             0x00

typedef  ANSC_ASN1_CHOICE ANSC_ASN1_SIGNATUREPARAMETERS, *PANSC_ASN1_SIGNATUREPARAMETERS;

#define  ACCESS_ANSC_ASN1_SIGNATUREPARAMETERS(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_SIGNATUREPARAMETERS, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DIGESTALGORITHMIDENTIFIER

 DigestAlgorithmIdentifier ::= AlgorithmIdentifier 

 **********************************************************************/

typedef  ANSC_ASN1_ALGORITHMIDENTIFIER ANSC_ASN1_DIGESTALGORITHMIDENTIFIER,    \
         *PANSC_ASN1_DIGESTALGORITHMIDENTIFIER;

#define  ACCESS_ANSC_ASN1_DIGESTALGORITHMIDENTIFIER(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DIGESTALGORITHMIDENTIFIER, Linkage)

/**********************************************************************

 OBJECT -- ANSC_ASN1_DHKEYAGREEMENT

 DHKeyAgreement ::= Sequence 
     {
                                 p Integer 
                                 g Integer 
                       priValueLen Integer OPT
     }

 **********************************************************************/

#define  ANSC_ASN1_DHKEYAGREEMENT_CLASS_CONTENT         ANSC_ASN1_SEQUENCE_CLASS_CONTENT

typedef  struct
_ANSC_ASN1_DHKEYAGREEMENT
{
    ANSC_ASN1_DHKEYAGREEMENT_CLASS_CONTENT
}
ANSC_ASN1_DHKEYAGREEMENT,  *PANSC_ASN1_DHKEYAGREEMENT;

#define  ACCESS_ANSC_ASN1_DHKEYAGREEMENT(p)    \
         ACCESS_CONTAINER(p, ANSC_ASN1_DHKEYAGREEMENT, Linkage)


#endif  /* _ANSC_ASN1_ALGORITHMIDENTIFIER_INTERFACE_H */

