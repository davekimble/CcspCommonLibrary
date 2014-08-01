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

    module:	tls_mco_global.h

        For Transport Layer Security Implementation (TLS),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file includes all the header files required by
        the Tls Module Container implementation.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        09/13/02    initial revision.

**********************************************************************/


#ifndef  _TLS_MCO_GLOBAL_
#define  _TLS_MCO_GLOBAL_


#include "ansc_platform.h"
#include "ansc_crypto_interface.h"
#include "ansc_crypto_external_api.h"
#include "ansc_object_mapper_interface.h"
#include "ansc_object_mapper_external_api.h"
#include "ansc_mco_interface.h"
#include "ansc_mco_external_api.h"
#include "ansc_atoproto_interface.h"
#include "ansc_atoproto_external_api.h"
#include "ansc_qio_interface.h"
#include "ansc_qio_external_api.h"

#include "ansc_ifo_csp.h"
#include "ansc_ifo_iqc.h"

#include "tls_co_oid.h"
#include "tls_co_name.h"
#include "tls_co_type.h"
#include "tls_properties.h"

#include "tls_mco_interface.h"
#include "tls_mco_exported_api.h"
#include "tls_mco_internal_api.h"

#include "tls_eco_interface.h"
#include "tls_eco_exported_api.h"


#endif