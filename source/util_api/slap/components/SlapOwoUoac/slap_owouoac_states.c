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

    module:	slap_owouoac_states.c

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Slap Owo Uoac Object.

        *   SlapOwoUoacReset

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        09/11/03    initial revision.

**********************************************************************/


#include "slap_owouoac_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SlapOwoUoacReset
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
SlapOwoUoacReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_OWO_UOAC_OBJECT           pMyObject    = (PSLAP_OWO_UOAC_OBJECT)hThisObject;

    pMyObject->CleanOwoTable((ANSC_HANDLE)pMyObject);

    SlapOwoReset((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}
