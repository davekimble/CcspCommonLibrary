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

    module:	sys_rrohcxt_interface.h

        For BroadWay Runtime System Environment (SYS),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2002
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This wrapper file defines the base class data structure and
        interface for the Sys Rro Hcxt Objects.

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


#ifndef  _SYS_RROHCXT_INTERFACE_
#define  _SYS_RROHCXT_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "sys_rro_interface.h"
#include "sys_rro_exported_api.h"


/***********************************************************
           SYS RRO HCXT COMPONENT OBJECT DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the os wrapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support), we
 * have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_SYSRROHCXT_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_SYSRROHCXT_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_SYSRROHCXT_GET_VALUE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_SYSRROHCXT_SET_VALUE)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 value
    );

/*
 * I don't even remember how many times I have to write something like this: a tree-liked data
 * repository with a few pre-defined data types. XML parser, ASN.1 coder/decoder, Configuration
 * File parser, ... to name a few. Why do we have to reimplement such construct every time? Why
 * is a general object not gonna meet all the requirements? Answer: there's no silver-bullet?
 */
#define  SYS_RRO_HCXT_CLASS_CONTENT                                                         \
    /* duplication of the base object class content */                                      \
    SYS_REPOSITORY_RECORD_CLASS_CONTENT                                                     \
    /* start of object class content */                                                     \
    ANSC_HANDLE                     RecordValue;                                            \
                                                                                            \
    PFN_SYSRROHCXT_GET_VALUE        GetRecordValue;                                         \
    PFN_SYSRROHCXT_SET_VALUE        SetRecordValue;                                         \
    /* end of object class content */                                                       \

typedef  struct
_SYS_RRO_HCXT_OBJECT
{
    SYS_RRO_HCXT_CLASS_CONTENT
}
SYS_RRO_HCXT_OBJECT,  *PSYS_RRO_HCXT_OBJECT;

#define  ACCESS_SYS_RRO_HCXT_OBJECT(p)              \
         ACCESS_CONTAINER(p, SYS_RRO_HCXT_OBJECT, Linkage)


#endif