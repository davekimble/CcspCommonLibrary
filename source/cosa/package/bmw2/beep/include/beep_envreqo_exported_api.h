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

    module:	beep_envreqo_exported_api.h

        For BSP Execution Environment Plane Implementation (BEEP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the exported functions provided by the Beep Env Request
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        05/23/03    initial revision.
        07/03/03    revisit when implementation phase starts

**********************************************************************/


#ifndef  _BEEP_ENVREQO_EXPORTED_API_
#define  _BEEP_ENVREQO_EXPORTED_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BEEP_ENVREQO_INTERFACE.C
***********************************************************/

ANSC_HANDLE
BeepCreateEnvRequest
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
         FUNCTIONS IMPLEMENTED IN BEEP_ENVREQO_BASE.C
***********************************************************/

ANSC_HANDLE
BeepEnvReqoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
BeepEnvReqoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BeepEnvReqoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BeepEnvReqoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );


#endif
