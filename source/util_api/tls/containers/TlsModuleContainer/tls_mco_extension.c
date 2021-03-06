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

    module:	tls_mco_extension.c

        For Transport Layer Security Implementation (TLS),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Tls Module Container Object.

        *   TlsMcoEnrollExtensionObjects
        *   TlsMcoManufactureExtensionObjects
        *   TlsMcoDestroyExtensionObjects

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        09/13/03    initial revision.

**********************************************************************/


#include "tls_mco_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsMcoEnrollExtensionObjects
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to enroll all the internal objects.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsMcoEnrollExtensionObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsMcoManufactureExtensionObjects
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to manufacture all the internal objects.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsMcoManufactureExtensionObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsMcoDestroyExtensionObjects
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to destroy all the internal objects.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsMcoDestroyExtensionObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}
