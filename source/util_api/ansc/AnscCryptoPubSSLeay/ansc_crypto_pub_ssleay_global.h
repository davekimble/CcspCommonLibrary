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

    module:	ansc_crypto_pub_ssleay_global.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2001
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file includes all the header files required by
        the Crypto Object implementation.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Kang Quan

    ---------------------------------------------------------------

    revision:

        05/13/02    initial revision.

**********************************************************************/


#ifndef  _ANSC_CRYPTO_PUB_SSLEAY_GLOBAL_
#define  _ANSC_CRYPTO_PUB_SSLEAY_GLOBAL_

#include "ansc_platform.h"

#include "ansc_crypto_pub.h"

/* our crypto under opensource is only used by windows simulation */
#ifdef _ANSC_WINDOWSNT
#include "../../opensource/crypto/crypto.h"
#include "../../opensource/crypto/bn.h"
#include "../../opensource/crypto/dh.h"
#include "../../opensource/crypto/objects.h"
#include "../../opensource/crypto/rsa.h"
#include "../../opensource/crypto/dsa.h"
#else 
/* need to set include path to the Linux ssl header */
#include "openssl/crypto.h"
#include "openssl/bn.h"
#include "openssl/dh.h"
#include "openssl/objects.h"
#include "openssl/rsa.h"
#include "openssl/dsa.h"
#endif

#include "ansc_crypto_pub_ssleay_interface.h"
#include "ansc_crypto_pub_ssleay_internal_api.h"
#include "ansc_crypto_pub_ssleay_external_api.h"
#include "ansc_crypto_pub_ssleay_util.h"

#endif
