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

    module:	slap_bmc2outo_internal_api.h

        For Service Logic Aggregation Plane Implementation (SLAP),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2005
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Slap Bmc2 Output
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        06/29/05    initial revision.

**********************************************************************/


#ifndef  _SLAP_BMC2OUTO_INTERNAL_API_
#define  _SLAP_BMC2OUTO_INTERNAL_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN SLAP_BMC2OUTO_STATES.C
***********************************************************/

ANSC_STATUS
SlapBmc2OutoReset
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
       FUNCTIONS IMPLEMENTED IN SLAP_BMC2OUTO_ACCESS.C
***********************************************************/

ANSC_STATUS
SlapBmc2OutoClear
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
SlapBmc2OutoWrite
    (
        ANSC_HANDLE                 hThisObject,
        char*                       pContent
    );

ANSC_STATUS
SlapBmc2OutoEraseLine
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
SlapBmc2OutoMoveCursor
    (
        ANSC_HANDLE                 hThisObject,
        char*                       pDirection      /* UP/DOWN/LEFT/RIGHT/HOME/END */
    );

#endif