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

    module:	ansc_lpccotcp_interface.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2003
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the Lpcco Tcp Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        08/23/03    initial revision.

**********************************************************************/


#ifndef  _ANSC_LPCCOTCP_INTERFACE_
#define  _ANSC_LPCCOTCP_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_lpcco_interface.h"
#include "ansc_lpcco_external_api.h"
#include "ansc_dstowo_interface.h"
#include "ansc_bstowo_interface.h"


/***********************************************************
      PLATFORM INDEPENDENT LPCCO TCP OBJECT DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the object mapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_LPCCOTCP_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_LPCCOTCP_GET_IF)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SET_IF)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hInterface
    );

typedef  PUCHAR
(*PFN_LPCCOTCP_GET_ADDR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SET_ADDR)
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      address
    );

typedef  USHORT
(*PFN_LPCCOTCP_GET_PORT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SET_PORT)
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      port
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SEND1)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SEND2)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket,
        void*                       buffer,
        ULONG                       ulSize,
        ULONG                       ulSeqNumber,
        ULONG                       ulReqType
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_SEND3)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket,
        void*                       buffer,
        ULONG                       ulSize,
        ULONG                       ulSeqNumber,
        ULONG                       ulReqType,
        ULONG                       ulRepCode
    );

typedef  ANSC_STATUS
(*PFN_LPCCOTCP_RECV1)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket,
        ANSC_HANDLE                 hBufferDesp
    );

/*
 * The Ansc Lpcco Tcp object implements the IMC interface by encapsulating the LPC calls as tcp
 * messages and transmit them over TCP socket. Such mechanism applies to most of the communication
 * scenarios on desktop operating systems, except the interaction between a User-mode module and a
 * Kernel-mode module, which requires some special consideration.
 */
#define  ANSC_LPCCO_TCP_CLASS_CONTENT                                                       \
    /* duplication of the base object class content */                                      \
    ANSC_LPC_CONNECTOR_CLASS_CONTENT                                                        \
    /* start of object class content */                                                     \
    ANSC_HANDLE                     hDaemonServer;                                          \
    ANSC_HANDLE                     hBrokerServer;                                          \
    ANSC_HANDLE                     hDaemonWorker;                                          \
    ANSC_HANDLE                     hBrokerWorker;                                          \
                                                                                            \
    ANSC_IPV4_ADDRESS               MyAddress;                                              \
    USHORT                          MyPort;                                                 \
    ANSC_IPV4_ADDRESS               ManagerAddress;                                         \
    USHORT                          ManagerPort;                                            \
    ULONG                           MaxMessageSize;                                         \
    ULONG                           EngineCount;                                            \
    ULONG                           MinSocketCount;                                         \
    ULONG                           MaxSocketCount;                                         \
    ULONG                           SocketTimeOut;                                          \
                                                                                            \
    PFN_LPCCOTCP_GET_ADDR           GetMyAddress;                                           \
    PFN_LPCCOTCP_SET_ADDR           SetMyAddress;                                           \
    PFN_LPCCOTCP_GET_PORT           GetMyPort;                                              \
    PFN_LPCCOTCP_SET_PORT           SetMyPort;                                              \
    PFN_LPCCOTCP_GET_ADDR           GetManagerAddress;                                      \
    PFN_LPCCOTCP_SET_ADDR           SetManagerAddress;                                      \
    PFN_LPCCOTCP_GET_PORT           GetManagerPort;                                         \
    PFN_LPCCOTCP_SET_PORT           SetManagerPort;                                         \
                                                                                            \
    PFN_LPCCOTCP_SEND1              SendHello;                                              \
    PFN_LPCCOTCP_SEND1              SendAck;                                                \
    PFN_LPCCOTCP_SEND2              SendRequest;                                            \
    PFN_LPCCOTCP_SEND3              SendReply;                                              \
    PFN_LPCCOTCP_SEND1              SendBye;                                                \
                                                                                            \
    PFN_LPCCOTCP_RECV1              Recv;                                                   \
    PFN_LPCCOTCP_RECV1              RecvHello;                                              \
    PFN_LPCCOTCP_RECV1              RecvAck;                                                \
    PFN_LPCCOTCP_RECV1              RecvRequest;                                            \
    PFN_LPCCOTCP_RECV1              RecvReply;                                              \
    PFN_LPCCOTCP_RECV1              RecvBye;                                                \
                                                                                            \
    PFN_DSTOWO_INIT                 DwoInit;                                                \
    PFN_DSTOWO_UNLOAD               DwoUnload;                                              \
    PFN_DSTOWO_ACCEPT               DwoAccept;                                              \
    PFN_DSTOWO_SETOUT               DwoSetOut;                                              \
    PFN_DSTOWO_REMOVE               DwoRemove;                                              \
    PFN_DSTOWO_QUERY                DwoQuery;                                               \
    PFN_DSTOWO_PROCESS              DwoProcessSync;                                         \
    PFN_DSTOWO_PROCESS              DwoProcessAsync;                                        \
    PFN_DSTOWO_COMPLETE             DwoSendComplete;                                        \
    PFN_DSTOWO_NOTIFY               DwoNotify;                                              \
                                                                                            \
    PFN_BSTOWO_INIT                 BwoInit;                                                \
    PFN_BSTOWO_UNLOAD               BwoUnload;                                              \
    PFN_BSTOWO_ACCEPT               BwoAccept;                                              \
    PFN_BSTOWO_REMOVE               BwoRemove;                                              \
    PFN_BSTOWO_QUERY                BwoQuery;                                               \
    PFN_BSTOWO_PROCESS              BwoProcessSync;                                         \
    PFN_BSTOWO_PROCESS              BwoProcessAsync;                                        \
    PFN_BSTOWO_COMPLETE             BwoSendComplete;                                        \
    PFN_BSTOWO_NOTIFY               BwoNotify;                                              \
    /* end of object class content */                                                       \

typedef  struct
_ANSC_LPCCO_TCP_OBJECT
{
    ANSC_LPCCO_TCP_CLASS_CONTENT
}
ANSC_LPCCO_TCP_OBJECT,  *PANSC_LPCCO_TCP_OBJECT;

#define  ACCESS_ANSC_LPCCO_TCP_OBJECT(p)            \
         ACCESS_CONTAINER(p, ANSC_LPCCO_TCP_OBJECT, Linkage)


#endif
