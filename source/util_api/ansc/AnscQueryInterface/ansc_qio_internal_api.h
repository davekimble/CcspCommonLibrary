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

    module:	ansc_qio_internal_api.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2002
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the external functions provided by the Query Interface
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        05/11/02    initial revision.

**********************************************************************/


#ifndef  _ANSC_QIO_INTERNAL_API_
#define  _ANSC_QIO_INTERNAL_API_


/***********************************************************
        FUNCTIONS IMPLEMENTED IN ANSC_QIO_OPERATION.C
***********************************************************/

ANSC_STATUS
AnscQioAddIf
    (
        ANSC_HANDLE                 hThisObject,
        char*                       pIfName,
        ANSC_HANDLE                 hInterface
    );

ANSC_STATUS
AnscQioDelIf
    (
        ANSC_HANDLE                 hThisObject,
        char*                       pIfName
    );

ANSC_HANDLE
AnscQioQueryIf
    (
        ANSC_HANDLE                 hThisObject,
        char*                       pIfName
    );


#endif
