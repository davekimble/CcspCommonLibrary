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

    module:	ansc_xsocket_external_api.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2002
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the external functions provided by the xsocket wrapper.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        05/28/02    initial revision.

**********************************************************************/


#ifndef  _ANSC_XSOCKET_EXTERNAL_API_
#define  _ANSC_XSOCKET_EXTERNAL_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN ANSC_XSOCKET_INTERFACE.C
***********************************************************/

ANSC_STATUS
AnscStartupXsocketWrapper
    (
        ANSC_HANDLE                 hOwnerContext
    );

ANSC_STATUS
AnscCleanupXsocketWrapper
    (
        ANSC_HANDLE                 hOwnerContext
    );

ANSC_HANDLE
AnscCreateXsocket
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
         FUNCTIONS IMPLEMENTED IN ANSC_XSOCKET_BASE.C
***********************************************************/

ANSC_HANDLE
AnscXsocketCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
AnscXsocketRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
AnscXsocketEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
AnscXsocketInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
AnscXsocketShutdown
    (
        ANSC_HANDLE                 hThisObject
    );


#endif
