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

    module:	slap_amo_states.c

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Slap Access Manager Object.

        *   SlapAmoGetSlapGoaIf
        *   SlapAmoGetSlapPoaIf
        *   SlapAmoGetSlapEnvController
        *   SlapAmoGetSlapLoamClient
        *   SlapAmoGetSlapLoamServer
        *   SlapAmoGetAnscLpcConnector
        *   SlapAmoGetProperty
        *   SlapAmoSetProperty
        *   SlapAmoResetProperty
        *   SlapAmoReset

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        09/03/03    initial revision.

**********************************************************************/


#include "slap_amo_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetSlapGoaIf
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetSlapGoaIf
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hSlapGoaIf;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetSlapPoaIf
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetSlapPoaIf
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hSlapPoaIf;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetSlapEnvController
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetSlapEnvController
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hSlapEnvController;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetSlapLoamClient
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetSlapLoamClient
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hSlapLoamClient;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetSlapLoamServer
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetSlapLoamServer
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hSlapLoamServer;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        SlapAmoGetAnscLpcConnector
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
SlapAmoGetAnscLpcConnector
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  pMyObject->hAnscLpcConnector;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapAmoGetProperty
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hProperty
            );

    description:

        This function is called to retrieve object property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hProperty
                Specifies the property data structure to be filled.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SlapAmoGetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    *(PSLAP_ACCESS_MANAGER_PROPERTY)hProperty = *pProperty;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapAmoSetProperty
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hProperty
            );

    description:

        This function is called to configure object property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hProperty
                Specifies the property data structure to be copied.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SlapAmoSetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    *pProperty = *(PSLAP_ACCESS_MANAGER_PROPERTY)hProperty;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapAmoResetProperty
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset object property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SlapAmoResetProperty
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    pProperty->AggregationMode      = SLAP_GOA_MODE_thisProcess;
    pProperty->LpcPartyPort         = ANSC_LPC_MANAGER_PORT_NUMBER + 1 + (USHORT)((ULONG)AnscGetProcessId() % ANSC_LPC_MANAGER_PORT_NUMBER);

    pProperty->MyAddress.Value      = IPV4_LOOPBACK_ADDRESS;
    pProperty->ManagerAddress.Value = IPV4_LOOPBACK_ADDRESS;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapAmoReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset object states.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SlapAmoReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_ACCESS_MANAGER_OBJECT     pMyObject    = (PSLAP_ACCESS_MANAGER_OBJECT  )hThisObject;
    PSLAP_ACCESS_MANAGER_PROPERTY   pProperty    = (PSLAP_ACCESS_MANAGER_PROPERTY)&pMyObject->Property;

    return  ANSC_STATUS_SUCCESS;
}