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

    module:	slap_oao_exported_api.h

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the exported functions provided by the Slap Obj Agent
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        09/29/03    initial revision.

**********************************************************************/


#ifndef  _SLAP_OAO_EXPORTED_API_
#define  _SLAP_OAO_EXPORTED_API_


/***********************************************************
        FUNCTIONS IMPLEMENTED IN SLAP_OAO_INTERFACE.C
***********************************************************/

ANSC_HANDLE
SlapCreateObjAgent
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
           FUNCTIONS IMPLEMENTED IN SLAP_OAO_BASE.C
***********************************************************/

ANSC_HANDLE
SlapOaoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
SlapOaoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
SlapOaoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
SlapOaoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
          FUNCTIONS IMPLEMENTED IN SLAP_OAO_STATES.C
***********************************************************/

ANSC_STATUS
SlapOaoReset
    (
        ANSC_HANDLE                 hThisObject
    );


#endif