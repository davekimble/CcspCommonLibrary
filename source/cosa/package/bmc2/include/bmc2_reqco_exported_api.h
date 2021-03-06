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

    module:	bmc2_reqco_exported_api.h

        For Broadway Management Console v2.0 Implementation (BMC2),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2005
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the exported functions provided by the Bmc2 Req Controller
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        06/23/05    initial revision.

**********************************************************************/


#ifndef  _BMC2_REQCO_EXPORTED_API_
#define  _BMC2_REQCO_EXPORTED_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN BMC2_REQCO_INTERFACE.C
***********************************************************/

ANSC_HANDLE
Bmc2CreateReqController
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
         FUNCTIONS IMPLEMENTED IN BMC2_REQCO_BASE.C
***********************************************************/

ANSC_HANDLE
Bmc2ReqcoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
Bmc2ReqcoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
Bmc2ReqcoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
Bmc2ReqcoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );


#endif
