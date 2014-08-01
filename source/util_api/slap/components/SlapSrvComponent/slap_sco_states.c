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

    module:	slap_sco_states.c

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Slap Srv Component Object.

        *   SlapScoGetObjName2
        *   SlapScoSetObjName
        *   SlapScoGetObjType
        *   SlapScoReset

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        07/06/03    initial revision.

**********************************************************************/


#include "slap_sco_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        char*
        SlapScoGetObjName2
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve object state. Note that the
        difference between this function and GetObjName() is that this
        function is registered as a SLAP call, therefore it must return
        a cloned string.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

char*
SlapScoGetObjName2
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SRV_COMPONENT_OBJECT      pMyObject    = (PSLAP_SRV_COMPONENT_OBJECT)hThisObject;

    return  AnscCloneString(pMyObject->ObjName);
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapScoSetObjName
            (
                ANSC_HANDLE                 hThisObject,
                char*                       obj_name
            );

    description:

        This function is called to configure object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                char*                       obj_name
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SlapScoSetObjName
    (
        ANSC_HANDLE                 hThisObject,
        char*                       obj_name
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SRV_COMPONENT_OBJECT      pMyObject    = (PSLAP_SRV_COMPONENT_OBJECT)hThisObject;

    if ( pMyObject->ObjName )
    {
        AnscFreeMemory(pMyObject->ObjName);

        pMyObject->ObjName = NULL;
    }

    if ( obj_name )
    {
        pMyObject->ObjName = (char*)AnscAllocateMemory(AnscSizeOfString(obj_name) + 1);

        if ( pMyObject->ObjName )
        {
            AnscCopyString(pMyObject->ObjName, obj_name);
        }
    }
    else
    {
        pMyObject->ObjName = (char*)AnscAllocateMemory(1);
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        SlapScoGetObjType
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

ULONG
SlapScoGetObjType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SRV_COMPONENT_OBJECT      pMyObject    = (PSLAP_SRV_COMPONENT_OBJECT)hThisObject;

    return  pMyObject->ObjType;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapScoReset
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
SlapScoReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SRV_COMPONENT_OBJECT      pMyObject    = (PSLAP_SRV_COMPONENT_OBJECT)hThisObject;

    return  ANSC_STATUS_SUCCESS;
}