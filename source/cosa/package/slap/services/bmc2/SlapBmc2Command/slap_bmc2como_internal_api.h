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

    module:	slap_bmc2como_internal_api.h

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2005
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Slap Bmc2 Command
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        06/28/05    initial revision.

**********************************************************************/


#ifndef  _SLAP_BMC2COMO_INTERNAL_API_
#define  _SLAP_BMC2COMO_INTERNAL_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN SLAP_BMC2COMO_STATES.C
***********************************************************/

ANSC_STATUS
SlapBmc2ComoReset
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
     FUNCTIONS IMPLEMENTED IN SLAP_BMC2COMO_COLLECTION.C
***********************************************************/

SLAP_UINT32
SlapBmc2ComoGetCount
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
       FUNCTIONS IMPLEMENTED IN SLAP_BMC2COMO_ACCESS.C
***********************************************************/

char*
SlapBmc2ComoGetCommandName
    (
        ANSC_HANDLE                 hThisObject
    );

SLAP_VARIABLE*
SlapBmc2ComoGetParamByIndex
    (
        ANSC_HANDLE                 hThisObject,
        SLAP_UINT32                 param_index
    );

ANSC_STATUS
SlapBmc2ComoRemoveAllParams
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
SlapBmc2ComoSetParamByIndex
    (
        ANSC_HANDLE                 hThisObject,
        SLAP_UINT32                 param_index,
        char*                       param_value
    );

SLAP_BOOL
SlapBmc2ComoIsAborted
    (
        ANSC_HANDLE                 hThisObject
    );


#endif
