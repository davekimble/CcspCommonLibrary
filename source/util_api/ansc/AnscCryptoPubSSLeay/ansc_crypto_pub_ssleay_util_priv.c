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

    Module:	ansc_crypto_pub_ssleay_util.c

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    Copyright:

        Cisco Systems, Inc., 1997~2001
        All Rights Reserved.

    ---------------------------------------------------------------

    Functional Description:

        Utilities for using SSLeay

    ---------------------------------------------------------------

    Environment:

        System Independent

    ---------------------------------------------------------------

    Author:

        Kang Quan

    ---------------------------------------------------------------

    Revision history:

        *   05/13/02    initial revision

**********************************************************************/

#include "ansc_crypto_pub_ssleay_global.h"

void
AnscCryptoPubBigNum2Integer
    (
        BIGNUM                      *pBigNum,
        PANSC_CRYPTO_INTEGER        pInteger
    )
{
    ANSC_CRYPTO_INTEGER             anInt;   

    if (!pBigNum || !pInteger)
        return;

    anInt.Length = 4;
    AnscCryptoPubBigEndianInteger2Integer(pInteger, &anInt);
}

void
AnscCryptoPubBigNum2Prime
    (
        BIGNUM                      *pBigNum,
        PANSC_CRYPTO_PRIME          pPrime
    )
{
    ANSC_CRYPTO_PRIME               aPrime;   
    
    if (!pBigNum || !pPrime)
        return;
    aPrime.Length = 4;
    AnscCryptoPubBigEndianPrime2Prime(pPrime, &aPrime);
}


