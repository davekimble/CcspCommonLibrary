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

    module:	slap_scobuf_buffer.c

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced object element-access
        functions of the Slap Sco Buffer Object.

        *   SlapScoBufGetSize
        *   SlapScoBufGetData

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        07/14/03    initial revision.

**********************************************************************/


#include "slap_scobuf_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        SLAP_UINT32
        SlapScoBufGetSize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the buffer size.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     buffer size.

**********************************************************************/

SLAP_UINT32
SlapScoBufGetSize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SCO_BUFFER_OBJECT         pMyObject    = (PSLAP_SCO_BUFFER_OBJECT)hThisObject;
    PSLAP_OLA_INTERFACE             pSlapOlaIf   = (PSLAP_OLA_INTERFACE    )pMyObject->hSlapOlaIf;

    return  0;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        SLAP_UCHAR_ARRAY*
        SlapScoBufGetData
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the buffer data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     buffer data.

**********************************************************************/

SLAP_UCHAR_ARRAY*
SlapScoBufGetData
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSLAP_SCO_BUFFER_OBJECT         pMyObject    = (PSLAP_SCO_BUFFER_OBJECT)hThisObject;
    PSLAP_OLA_INTERFACE             pSlapOlaIf   = (PSLAP_OLA_INTERFACE    )pMyObject->hSlapOlaIf;

    return  NULL;
}
