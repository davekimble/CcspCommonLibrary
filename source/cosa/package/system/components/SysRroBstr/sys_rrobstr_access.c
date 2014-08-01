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

    module:	sys_rrobstr_access.c

        For BroadWay Runtime System Environment (SYS),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2002
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced field-access functions
        of the Sys Rro Bstr Object.

        *   SysRroBstrGetRecordData
        *   SysRroBstrSetRecordData
        *   SysRroBstrGetRecordValue
        *   SysRroBstrSetRecordValue

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        05/07/02    initial revision.

**********************************************************************/


#include "sys_rrobstr_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SysRroBstrGetRecordData
            (
                ANSC_HANDLE                 hThisObject,
                PVOID                       pDataBuffer,
                PULONG                      pulDataSize
            );

    description:

        This function is called to retrieve the record data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PVOID                       pDataBuffer
                Specifies the buffer holding the record data.

                PULONG                      pulDataSize
                Specifies the size of the record data buffer.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SysRroBstrGetRecordData
    (
        ANSC_HANDLE                 hThisObject,
        PVOID                       pDataBuffer,
        PULONG                      pulDataSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSYS_RRO_BSTR_OBJECT            pMyObject    = (PSYS_RRO_BSTR_OBJECT)hThisObject;

    if ( *pulDataSize < pMyObject->RecordSize )
    {
        return  ANSC_STATUS_BAD_SIZE;
    }

    if ( pMyObject->RecordValue )
    {
        AnscCopyMemory
            (
                pDataBuffer,
                pMyObject->RecordValue,
                pMyObject->RecordSize
            );

        *pulDataSize = pMyObject->RecordSize;
    }
    else
    {
        *pulDataSize = 0;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SysRroBstrSetRecordData
            (
                ANSC_HANDLE                 hThisObject,
                PVOID                       pDataBuffer,
                ULONG                       ulDataSize
            );

    description:

        This function is called to configure the record data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PVOID                       pDataBuffer
                Specifies the buffer holding the record data.

                ULONG                       ulDataSize
                Specifies the size of the record data buffer.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SysRroBstrSetRecordData
    (
        ANSC_HANDLE                 hThisObject,
        PVOID                       pDataBuffer,
        ULONG                       ulDataSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSYS_RRO_BSTR_OBJECT            pMyObject    = (PSYS_RRO_BSTR_OBJECT)hThisObject;

    if ( pMyObject->RecordValue )
    {
        AnscFreeMemory(pMyObject->RecordValue);
    }

    if ( pDataBuffer && ulDataSize )
    {
        pMyObject->RecordValue = AnscAllocateMemory(ulDataSize + 1);
        pMyObject->RecordSize  = ulDataSize;

        if ( !pMyObject->RecordValue )
        {
            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            AnscCopyMemory
                (
                    pMyObject->RecordValue,
                    pDataBuffer,
                    ulDataSize
                );
        }
    }
    else
    {
        pMyObject->RecordValue = NULL;
        pMyObject->RecordSize  = 0;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        SysRroBstrGetRecordValue
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the record data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     record value.

**********************************************************************/

PUCHAR
SysRroBstrGetRecordValue
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSYS_RRO_BSTR_OBJECT            pMyObject    = (PSYS_RRO_BSTR_OBJECT)hThisObject;

    return  pMyObject->RecordValue;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        SysRroBstrSetRecordValue
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                      value,
                ULONG                       size
            );

    description:

        This function is called to configure the record data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PUCHAR                      value
                Specifies the record value to be configured.

                ULONG                       size
                Specifies the size of the record value.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
SysRroBstrSetRecordValue
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      value,
        ULONG                       size
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PSYS_RRO_BSTR_OBJECT            pMyObject    = (PSYS_RRO_BSTR_OBJECT)hThisObject;

    if ( pMyObject->RecordValue )
    {
        AnscFreeMemory(pMyObject->RecordValue);
    }

    if ( value && size )
    {
        pMyObject->RecordValue = AnscAllocateMemory(size + 1);
        pMyObject->RecordSize  = size;

        if ( !pMyObject->RecordValue )
        {
            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            AnscCopyMemory
                (
                    pMyObject->RecordValue,
                    value,
                    size
                );
        }
    }
    else
    {
        pMyObject->RecordValue = NULL;
        pMyObject->RecordSize  = 0;
    }

    return  ANSC_STATUS_SUCCESS;
}