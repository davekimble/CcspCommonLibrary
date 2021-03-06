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

    module:	ansc_dkuo_states.c

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2001
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Ansc Daemon Socket Udp Object.

        *   AnscDkuoGetPeerAddress
        *   AnscDkuoSetPeerAddress
        *   AnscDkuoGetPeerPort
        *   AnscDkuoSetPeerPort
        *   AnscDkuoGetDaemonServer
        *   AnscDkuoSetDaemonServer
        *   AnscDkuoGetDaemonEngine
        *   AnscDkuoSetDaemonEngine
        *   AnscDkuoGetClientContext
        *   AnscDkuoSetClientContext
        *   AnscDkuoGetPacket
        *   AnscDkuoSetPacket
        *   AnscDkuoReturn
        *   AnscDkuoReset

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        12/10/01    initial revision.

**********************************************************************/


#include "ansc_dkuo_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        AnscDkuoGetPeerAddress
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

PUCHAR
AnscDkuoGetPeerAddress
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->PeerAddress.Dot;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetPeerAddress
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                      address
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PUCHAR                      address
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetPeerAddress
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      address
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->PeerAddress.Value = *(PULONG)address;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        USHORT
        AnscDkuoGetPeerPort
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

USHORT
AnscDkuoGetPeerPort
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->PeerPort;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetPeerPort
            (
                ANSC_HANDLE                 hThisObject,
                USHORT                      usPort
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                USHORT                      usPort
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetPeerPort
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      usPort
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->PeerPort = usPort;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        AnscDkuoGetDaemonServer
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
AnscDkuoGetDaemonServer
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->hDaemonServer;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetDaemonServer
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDaemonServer
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDaemonServer
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetDaemonServer
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDaemonServer
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->hDaemonServer = hDaemonServer;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        AnscDkuoGetDaemonEngine
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
AnscDkuoGetDaemonEngine
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->hDaemonEngine;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetDaemonEngine
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDaemonEngine
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDaemonEngine
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetDaemonEngine
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDaemonEngine
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->hDaemonEngine = hDaemonEngine;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        AnscDkuoGetClientContext
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
AnscDkuoGetClientContext
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->hClientContext;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetClientContext
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hClientContext
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hClientContext
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetClientContext
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hClientContext
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->hClientContext = hClientContext;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        AnscDkuoGetPacket
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_HANDLE
AnscDkuoGetPacket
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    return  pMyObject->hPacket;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoSetPacket
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hPacket
            );

    description:

        This function is called to configure the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hPacket
                Specifies the object state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoSetPacket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPacket
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    AnscAcquireLock(&pMyObject->OpLock);
    pMyObject->hPacket = hPacket;
    AnscReleaseLock(&pMyObject->OpLock);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoReturn
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to return this socket object back to
        the global socket pool.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoReturn
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;
    PANSC_DAEMON_SERVER_UDP_OBJECT  pServer      = (PANSC_DAEMON_SERVER_UDP_OBJECT)pMyObject->hDaemonServer;
    PANSC_DAEMON_ENGINE_UDP_OBJECT  pEngine      = (PANSC_DAEMON_ENGINE_UDP_OBJECT)pMyObject->hDaemonEngine;

    returnStatus =
        pServer->ReleaseSocket
            (
                (ANSC_HANDLE)pServer,
                (ANSC_HANDLE)pMyObject
            );

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        AnscDkuoReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
AnscDkuoReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PANSC_DAEMON_SOCKET_UDP_OBJECT  pMyObject    = (PANSC_DAEMON_SOCKET_UDP_OBJECT)hThisObject;

    pMyObject->Socket         = ANSC_SOCKET_INVALID_SOCKET;
    pMyObject->HashIndex      = 0;

    pMyObject->hDaemonEngine  = (ANSC_HANDLE)NULL;
    pMyObject->hClientContext = (ANSC_HANDLE)NULL;
    pMyObject->hPacket        = (ANSC_HANDLE)NULL;
    pMyObject->RecvBytesCount = 0;
    pMyObject->SendBytesCount = 0;
    pMyObject->LastRecvAt     = 0;
    pMyObject->LastSendAt     = 0;
    pMyObject->bClosed        = TRUE;
    pMyObject->bRecvEnabled   = TRUE;
    pMyObject->bSendEnabled   = TRUE;

    return  ANSC_STATUS_SUCCESS;
}
