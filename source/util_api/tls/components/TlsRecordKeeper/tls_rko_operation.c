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

    module:	tls_rko_operation.c

        For Transport Layer Security Implementation (TLS),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the TLS Record Keeper Object.

        *   TlsRkoEngage
        *   TlsRkoCancel
        *   TlsRkoChangeStateW
        *   TlsRkoChangeStateR

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        05/26/03    initial revision.

**********************************************************************/


#include "tls_rko_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsRkoEngage
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to engage the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsRkoEngage
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PTLS_RECORD_KEEPER_OBJECT       pMyObject     = (PTLS_RECORD_KEEPER_OBJECT  )hThisObject;

    if ( pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }
    else
    {
        pMyObject->bActive = TRUE;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsRkoCancel
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to cancel the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsRkoCancel
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PTLS_RECORD_KEEPER_OBJECT       pMyObject     = (PTLS_RECORD_KEEPER_OBJECT  )hThisObject;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }
    else
    {
        pMyObject->bActive = FALSE;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsRkoChangeStateW
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hRecordState
            );

    description:

        This function is called to activate the pending record state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ANSC_HANDLE                 hRecordState
                Specifies the record state to be activated.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsRkoChangeStateW
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecordState
    )
{
    PTLS_RECORD_KEEPER_OBJECT       pMyObject     = (PTLS_RECORD_KEEPER_OBJECT  )hThisObject;
    PTLS_RECORD_STATE               pRecordStateW = (PTLS_RECORD_STATE          )&pMyObject->RecordStateW;

    *pRecordStateW = *(PTLS_RECORD_STATE)hRecordState;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        TlsRkoChangeStateR
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hRecordState
            );

    description:

        This function is called to activate the pending record state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ANSC_HANDLE                 hRecordState
                Specifies the record state to be activated.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
TlsRkoChangeStateR
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecordState
    )
{
    PTLS_RECORD_KEEPER_OBJECT       pMyObject     = (PTLS_RECORD_KEEPER_OBJECT  )hThisObject;
    PTLS_RECORD_STATE               pRecordStateR = (PTLS_RECORD_STATE          )&pMyObject->RecordStateR;

    *pRecordStateR = *(PTLS_RECORD_STATE)hRecordState;

    return  ANSC_STATUS_SUCCESS;
}
