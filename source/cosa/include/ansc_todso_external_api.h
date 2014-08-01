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

    module:	ansc_todso_external_api.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco System  , Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the external functions provided by the TOD Server Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        02/17/03    initial revision.

**********************************************************************/


#ifndef  _ANSC_TODSO_EXTERNAL_API_
#define  _ANSC_TODSO_EXTERNAL_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN ANSC_TODSO_INTERFACE.C
***********************************************************/

ANSC_HANDLE
AnscCreateTodServer
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
          FUNCTIONS IMPLEMENTED IN ANSC_TODSO_BASE.C
***********************************************************/

ANSC_HANDLE
AnscTodsoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
AnscTodsoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
AnscTodsoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
AnscTodsoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );


#endif