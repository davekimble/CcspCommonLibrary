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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dbus/dbus.h>
#include <ccsp_message_bus.h>
#include "ccsp_base_api.h"
#include "ccsp_trace.h"

#include <sys/time.h>
#include <time.h>

extern CCSP_DEADLOCK_DETECTION_INFO deadlock_detection_info;
extern int   CcspBaseIf_timeout_protect_plus_seconds;
extern int   CcspBaseIf_deadlock_detection_time_normal_seconds;
extern int   CcspBaseIf_deadlock_detection_time_getval_seconds;
extern int   CcspBaseIf_timeout_seconds;
extern int   CcspBaseIf_timeout_getval_seconds;
extern int   deadlock_detection_enable;
extern DEADLOCK_ARRAY*  deadlock_detection_log;
extern void* CcspBaseIf_Deadlock_Detection_Thread(void *);

// GLOBAL VAR
static int ccsp_bus_ref_count = 0;
static pthread_t thread_dbus_loop = 0;
static pthread_t thread_dbus_deadlock_monitor = 0;


// FUNCTION PROTOCOL
// internal functions

static void              path_unregistered_func(DBusConnection*, void*);
static DBusHandlerResult path_message_func(DBusConnection*, DBusMessage*, void*);
static DBusHandlerResult filter_func(DBusConnection*, DBusMessage*, void*);
static void*             CCSP_Message_Bus_Loop_Thread(void * ccsp_bus_info_ptr);
static void              append_event_info(char*, const char*, const char*, const char*, const char*);
static int               CCSP_Message_Bus_Register_Event_Priv(DBusConnection*, const char*, const char*, const char*, const char*, int);
static int               CCSP_Message_Save_Register_Event(void*, const char*, const char*, const char*, const char*);
static int               CCSP_Message_Bus_Register_Path_Priv(void*, const char*, DBusObjectPathMessageFunction, void*);
static int               analyze_reply(DBusMessage*, DBusMessage*, DBusMessage**);

static DBusConnection* createConnection(const char* address);
static DBusConnection* createListenerConnection(CCSP_MESSAGE_BUS_INFO *bus_info);
static DBusConnection* getSendConnection(CCSP_MESSAGE_BUS_INFO *bus_info);
static int CCSP_Message_Bus_Send_Str(
		DBusConnection *conn, char* component_id, const char* path,
		const char* interface, const char* method, char* request);

// External Interface, defined in ccsp_message_bus.h
/*
void CCSP_Msg_SleepInMilliSeconds(int milliSecond);
int  CCSP_Message_Bus_Init(char*, char*, void**, CCSP_MESSAGE_BUS_MALLOC, CCSP_MESSAGE_BUS_FREE);
void CCSP_Message_Bus_Exit(void *bus_handle);
int  CCSP_Message_Bus_Register_Event(void*, const char*, const char*, const char*, const char*);
int  CCSP_Message_Bus_UnRegister_Event(void*, const char*, const char*, const char*, const char*);
void CCSP_Message_Bus_Set_Event_Callback(void*, DBusObjectPathMessageFunction, void*);
#define CCSP_Message_Bus_Register_Path CCSP_Message_Bus_Register_Path2
int  CCSP_Message_Bus_Register_Path2(void*, const char*, DBusObjectPathMessageFunction, void*);
int  CCSP_Message_Bus_Send_Str(DBusConnection*, char*, const char*, const char*, const char*, char*);
int  CCSP_Message_Bus_Send_Msg(void*, DBusMessage*, int, DBusMessage**);
int  CCSP_Message_Bus_Send_Msg_Block(void*, DBusMessage*, int, DBusMessage**);
 */

// IMPLEMENTATION

//#define TRACE_ERROR CcspTraceError
//#define TRACE_DEBUG CcspTraceDebug

FILE* dfp = 0;
#define  MyTraceBase(arg ...)                                                       \
            do {                                                                  \
                fprintf(dfp, arg);                                         \
            } while (FALSE)
#define  MyTraceDebug(msg)                                           \
            if(dfp){                                                                                         \
                ANSC_UNIVERSAL_TIME ut; \
                AnscGetLocalTime(&ut);                                                               \
                fprintf(dfp, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d-",   \
                		ut.Year,ut.Month,ut.DayOfMonth,ut.Hour,ut.Minute,ut.Second); \
                MyTraceBase msg;                                                                \
                fflush(dfp); \
            }
#define TRACE_ERROR MyTraceDebug
#define TRACE_DEBUG MyTraceDebug
// TRACE_DEBUG(("<%s:%d>: here\n", __FUNCTION__, __LINE__));

void ccsp_message_debug(char* msg);
void ccsp_message_debug(char* msg) {
	TRACE_DEBUG(("%s\n", msg));
}

static void initDebug(char *component_id) {
	char debug_file[256];
	char* id = component_id;
	if(dfp) {
		TRACE_DEBUG(("<%s:%d>: subsequent init with cid='%s'\n", __FUNCTION__, __LINE__, component_id));
		return;
	}
	if(!id) id = "default";
	sprintf(debug_file, "/var/log/ccsp_bus/logs/%s.log", id);
	printf("opening file: '%s' \n", debug_file);
	if ((dfp = fopen(debug_file, "w")) == NULL) {
		return;
	}
	TRACE_DEBUG(("<%s:%d>: log start: %s\n", __FUNCTION__, __LINE__, component_id));
}

static void path_unregistered_func(DBusConnection *connection, void *user_data) {
	/* connection was finalized */
}

static DBusHandlerResult path_message_func(
		DBusConnection  *conn,
		DBusMessage     *message,
		void            *user_data
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)user_data;

	TRACE_DEBUG(("<%s:%d>: enter\n", __FUNCTION__, __LINE__));
	//push to a queue, signal the processing thread, then return immediately
	dbus_message_ref (message);

	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL)
		bus_info->sig_callback(conn, message, user_data);
	else if(bus_info->thread_msg_func)
		bus_info->thread_msg_func(conn, message, user_data);
	dbus_message_unref(message);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult filter_func(
		DBusConnection     *conn,
		DBusMessage        *message,
		void               *user_data
) {

	CCSP_MESSAGE_BUS_CONNECTION *connection = (CCSP_MESSAGE_BUS_CONNECTION *)user_data;
	CCSP_MESSAGE_BUS_INFO *bus_info =(CCSP_MESSAGE_BUS_INFO *) connection->bus_info_ptr;

	TRACE_DEBUG(("<%s:%d>: enter\n", __FUNCTION__, __LINE__));

	switch (dbus_message_get_type (message)) {
	case DBUS_MESSAGE_TYPE_SIGNAL:

		if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
			// This is normal at process exit

			// TRACE_DEBUG(("<%s>: Signal received: Bus disconnected!\n", __FUNCTION__));

			// no longer acted upon here

		} else {
			if(bus_info->sig_callback)
				path_message_func(conn, message, bus_info);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
		break;

	default:
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	}
}

















static DBusConnection* getSendConnection(CCSP_MESSAGE_BUS_INFO *bus_info) {

	DBusConnection* c = 0;
	pthread_mutex_lock(&bus_info->info_mutex);

	if(!bus_info->run) {
		pthread_mutex_unlock(&bus_info->info_mutex);
		return 0;
	}
	c = bus_info->_send_connection.conn;

	if(c) {
		if(dbus_connection_get_is_connected(c)) {
			pthread_mutex_unlock(&bus_info->info_mutex);
			return c;
		}
		dbus_connection_unref(c);
		c = 0;
	}
	c = createConnection(bus_info->_send_connection.address);
	if(c) dbus_connection_ref(c);
	pthread_mutex_unlock(&bus_info->info_mutex);
	return c;
}

static DBusConnection* createListenerConnection(CCSP_MESSAGE_BUS_INFO *bus_info) {

	DBusError error;
	DBusConnection *conn_new = 0;
	DBusConnection *conn_old = 0;
	int ret = 0;
	int i = 0;

	if(!bus_info) {
		TRACE_ERROR(("<%s:%d>: !bus_info\n", __FUNCTION__, __LINE__));
		return 0;
	}
	dbus_error_init (&error);

	while(bus_info->run) {
		conn_new = createConnection(bus_info->_listen_connection.address);
		if(!conn_new) {
			TRACE_ERROR(("<%s:%d>: !conn_new\n", __FUNCTION__, __LINE__));
			CCSP_Msg_SleepInMilliSeconds(200);
			continue;
		}

		if(bus_info->component_id && strlen(bus_info->component_id)) {
			TRACE_DEBUG(("<%s:%d>: registering: '%s'\n", __FUNCTION__, __LINE__, bus_info->component_id));
			ret = dbus_bus_request_name(
					conn_new, bus_info->component_id,
					DBUS_NAME_FLAG_ALLOW_REPLACEMENT|DBUS_NAME_FLAG_REPLACE_EXISTING|DBUS_NAME_FLAG_DO_NOT_QUEUE,
					&error
			);
			if (dbus_error_is_set (&error)) {
				TRACE_ERROR(("<%s>"
								"Failed to request name %s:"
								" ret=%d, error=%s\n",
								__FUNCTION__,
								bus_info->component_id,
								ret, error.message
						));
				dbus_error_free (&error);
				dbus_connection_close(conn_new);
				dbus_connection_unref (conn_new);
				continue;
			}

			if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER &&
					ret != DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER)
			{
				TRACE_ERROR((
								"<%s>"
								"Request name returned %d:"
								"someone already owns the name %s \n",
								__FUNCTION__,
								ret, bus_info->component_id
						));
				dbus_error_free (&error);
				dbus_connection_close(conn_new);
				dbus_connection_unref (conn_new);
				//                CCSP_Msg_SleepInMilliSeconds(3000);
				CCSP_Msg_SleepInMilliSeconds(200);
				continue;
			}
		}

		for(i = 0; i < CCSP_MESSAGE_BUS_MAX_PATH; i++) {
			if(bus_info->path_array[i].path != NULL) {
				dbus_connection_try_register_object_path(
						conn_new,
						bus_info->path_array[i].path,
						&bus_info->path_array[i].echo_vtable,
						bus_info->path_array[i].user_data,
						NULL
				);
			}
		}


		for(i = 0; i < CCSP_MESSAGE_BUS_MAX_FILTER; i++) {
			if(bus_info->filters[i].event != NULL) {
				CCSP_Message_Bus_Register_Event_Priv (
						conn_new,
						bus_info->filters[i].sender,
						bus_info->filters[i].path,
						bus_info->filters[i].interface,
						bus_info->filters[i].event,
						1
				);
			}
		}

		if ( ! dbus_connection_add_filter (conn_new, filter_func, &bus_info->_listen_connection, NULL)) {
			TRACE_ERROR(("<%s> Couldn't add filter!\n", __FUNCTION__));
			dbus_error_free (&error);
			dbus_connection_close(conn_new);
			dbus_connection_unref (conn_new);
			continue;
		}
		return conn_new;
	}

	//	if(conn_old) {
	//		dbus_connection_close(conn_old);
	//		dbus_connection_unref(conn_old);
	//	}
	return 0;
}

static DBusConnection* createConnection(const char* address) {
	DBusError error;
	DBusConnection *conn_new = NULL;

	//    TRACE_DEBUG(("<%s> connect started\n", __FUNCTION__));

	// uses "break" at the end to get out of this while loop

	dbus_error_init (&error);
	conn_new = dbus_connection_open_private (address, &error);
	if(conn_new == NULL) {
		TRACE_ERROR(("<%s> Failed to open connection to bus at %s: %s\n",
				__FUNCTION__, address, error.message));
		dbus_error_free (&error);
		return 0;
	}

	if ( ! dbus_bus_register (conn_new, &error)) {
		TRACE_ERROR(("<%s> Failed to register connection to bus at %s: %s\n",
				__FUNCTION__, address, error.message));
		dbus_error_free (&error);
		dbus_connection_close(conn_new);
		dbus_connection_unref (conn_new);
		return 0;
	}

	// Everything is ok
	dbus_error_free (&error);
	return conn_new;
}

static void* CCSP_Message_Bus_Loop_Thread(void* user_data) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)user_data;

	struct timeval now;
	struct timespec timeout;

	unsigned long                                 curTime        = 0;
	unsigned long                                 preTime        = 0;

	preTime  = time(NULL);

	while(bus_info->run) {

		TRACE_DEBUG(("<%s:%d>: start\n", __FUNCTION__, __LINE__));

		pthread_mutex_lock(&bus_info->info_mutex);
		if(bus_info->run && !bus_info->_listen_connection.conn) {
			// does not return until
			bus_info->_listen_connection.conn = createListenerConnection(bus_info);
		}
		pthread_mutex_unlock(&bus_info->info_mutex);

		if(!bus_info->run) {
			return NULL;
		}

		while(dbus_connection_read_write_dispatch(bus_info->_listen_connection.conn, 200)) {
//			printf("<%s>: here\n", __FUNCTION__);
//			TRACE_DEBUG(("<%s:%d>: here\n", __FUNCTION__, __LINE__));

			/* We leverage this pthread to check dbus connection. */
			curTime = time(NULL);
			if ( ( curTime-preTime ) > CCSP_MESSAGE_BUS_TIMEOUT_MAX_SECOND  ){
				CcspTraceWarning(("<%s> !!!!PSM mode switching happened. Send singal to check dbus connection\n", __FUNCTION__));
				CcspBaseIf_SendsystemKeepaliveSignal(bus_info);
			}
			preTime = curTime;
		}

		pthread_mutex_lock(&bus_info->info_mutex);
		dbus_connection_unref(bus_info->_listen_connection.conn);
		bus_info->_listen_connection.conn = 0;
		pthread_mutex_unlock(&bus_info->info_mutex);

		// recreate connection
	}

	return NULL;
}

static void append_event_info(
		char * destination,
		const char * sender,
		const char * path,
		const char * interface,
		const char * event_name
) {
	char buf[512] = {0};

	if(sender) {
		sprintf(buf,",sender='%s'", sender);
		strcat(destination, buf);
	}

	if(path) {
		sprintf(buf,",path='%s'", path);
		strcat(destination, buf);
	}

	if(interface) {
		sprintf(buf,",interface='%s'", interface);
		strcat(destination, buf);
	}

	if(event_name) {
		sprintf(buf,",member='%s'", event_name);
		strcat(destination, buf);
	}

	return;
}

static int CCSP_Message_Bus_Register_Event_Priv(
		DBusConnection *conn,
		const char* sender,
		const char* path,
		const char* interface,
		const char* event_name,
		int ifregister
) {
	char tmp[512] = {0};
	int  ret = 0;

	strcpy(tmp, "type='signal'");
	append_event_info(tmp, sender, path, interface, event_name);

	if(ifregister)
		ret = CCSP_Message_Bus_Send_Str(
				conn,
				DBUS_SERVICE_DBUS,
				DBUS_PATH_DBUS,
				DBUS_INTERFACE_DBUS,
				"AddMatch",
				tmp
		);
	else
		ret = CCSP_Message_Bus_Send_Str(
				conn,
				DBUS_SERVICE_DBUS,
				DBUS_PATH_DBUS,
				DBUS_INTERFACE_DBUS,
				"RemoveMatch",
				tmp
		);

	return ret;
}


static int CCSP_Message_Save_Register_Event(
		void* bus_handle,
		const char* sender,
		const char* path,
		const char* interface,
		const char* event_name
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	int i;

	pthread_mutex_lock(&bus_info->info_mutex);

	for(i = 0; i < CCSP_MESSAGE_BUS_MAX_FILTER; i++) {
		// find the first empty slot, save, and return
		if(bus_info->filters[i].used  == 0) {
			bus_info->filters[i].used = 1;

			if(path) {
				bus_info->filters[i].path = bus_info->mallocfunc(strlen(path)+1);
				strcpy(bus_info->filters[i].path, path);
			}

			if(interface) {
				bus_info->filters[i].interface = bus_info->mallocfunc(strlen(interface)+1);
				strcpy(bus_info->filters[i].interface, interface);
			}

			if(event_name) {
				bus_info->filters[i].event = bus_info->mallocfunc(strlen(event_name)+1);
				strcpy(bus_info->filters[i].event, event_name);
			}
			if(sender) {
				bus_info->filters[i].sender = bus_info->mallocfunc(strlen(sender)+1);
				strcpy(bus_info->filters[i].sender, sender);
			}

			pthread_mutex_unlock(&bus_info->info_mutex);
			return CCSP_Message_Bus_OK;
		}
	}

	// all slots are in use
	pthread_mutex_unlock(&bus_info->info_mutex);
	return CCSP_Message_Bus_OOM;
}

static int CCSP_Message_Bus_Register_Path_Priv(
		void* bus_handle,
		const char* path,
		DBusObjectPathMessageFunction funcptr,
		void * user_data
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	int ret = CCSP_Message_Bus_ERROR;
	DBusError error;

	int i, j;

	dbus_error_init (&error);
	pthread_mutex_lock(&bus_info->info_mutex);
	for(i = 0; i < CCSP_MESSAGE_BUS_MAX_PATH; i++) {
		if(bus_info->path_array[i].path == NULL) {
			bus_info->path_array[i].path = bus_info->mallocfunc(strlen(path)+1);
			strcpy(bus_info->path_array[i].path, path);
			bus_info->path_array[i].user_data = user_data ;
			bus_info->path_array[i].echo_vtable.unregister_function = path_unregistered_func;
			bus_info->path_array[i].echo_vtable.message_function = funcptr;

			break;
		}
	}
	if(i != CCSP_MESSAGE_BUS_MAX_PATH) {
		if(bus_info->_listen_connection.conn ) {
			if(dbus_connection_try_register_object_path (
					bus_info->_listen_connection.conn,
					path,
					&bus_info->path_array[i].echo_vtable,
					(void*)user_data,
					&error
			))
				ret = CCSP_Message_Bus_OK;
		}
	}

	pthread_mutex_unlock(&bus_info->info_mutex);
	dbus_error_free(&error);

	return ret;
}

static int analyze_reply(
		DBusMessage *message,
		DBusMessage *reply,
		DBusMessage **result
) {
	int ret  = CCSP_Message_Bus_ERROR;
	int type = dbus_message_get_type (reply);

	if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		if(result) *result =  reply;
		else dbus_message_unref(reply);

		ret = CCSP_Message_Bus_OK;
	} else {
		const char *err = dbus_message_get_error_name (reply);

		CcspTraceWarning(("<%s>: DbusSend error='%s', msg='%s'\n",
				__FUNCTION__, err, dbus_message_get_destination(message)));

		dbus_message_unref (reply);

		if(strcmp(err, DBUS_ERROR_SERVICE_UNKNOWN) == 0)
			ret = CCSP_MESSAGE_BUS_NOT_EXIST;
		else
			ret = CCSP_MESSAGE_BUS_NOT_SUPPORT;
	}

	return ret;
}

/*send a string _WITHOUT_ return param on specified connection*/
static int CCSP_Message_Bus_Send_Str(
		DBusConnection *conn,
		char* component_id,
		const char* path,
		const char* interface,
		const char* method,
		char* request
) {
	DBusMessage *message = NULL;
	DBusMessage *reply   = NULL;
	DBusPendingCall *pcall = NULL;
	CCSP_MESSAGE_BUS_CB_DATA *cb_data = NULL;

	int ret = CCSP_Message_Bus_ERROR;
	//    static int ct = 0;
	int type = 0;

	// construct base message
	message = dbus_message_new_method_call
			(
					component_id,
					path,
					interface,
					method
			);
	if ( ! message ) {
		TRACE_ERROR(("<%s>: No memory\n", __FUNCTION__));
		ret = CCSP_Message_Bus_OOM;
		goto EXIT;
	}

	cb_data = (CCSP_MESSAGE_BUS_CB_DATA *)malloc(sizeof(CCSP_MESSAGE_BUS_CB_DATA));
	if(cb_data == NULL) {
		TRACE_ERROR(("<%s>: No memory\n", __FUNCTION__));
		ret = CCSP_Message_Bus_OOM;
		goto EXIT;
	}
	cb_data->message = message;
	cb_data->succeed = 0;

	// append and send request
	dbus_message_append_args (message, DBUS_TYPE_STRING, &request,
			DBUS_TYPE_INVALID);
	// this won't get sent until
	TRACE_DEBUG(("<%s:%d>: sending :\n\t"
			"%s / %s / %s / %s \n\t %s \n",
			__FUNCTION__, __LINE__,
			component_id, path, interface,
			method, request));
	if (dbus_connection_send_with_reply(conn, message, &pcall, 2000) == 0 || pcall == NULL) {
		TRACE_ERROR(("<%s>: dbus_connection_send fail\n", __FUNCTION__));
		ret = CCSP_Message_Bus_ERROR;
		goto EXIT;
	}

	dbus_connection_flush(conn);

	// free message

//	// block until we recieve a reply - jlaue TODO check return
	dbus_pending_call_block(pcall);

	// get reply
	reply = dbus_pending_call_steal_reply(pcall);

	if(reply) {
		TRACE_DEBUG(("<%s>: reply received\n", __FUNCTION__));
		ret = analyze_reply(message, reply, NULL);
	} else {
		ret = CCSP_Message_Bus_OK;
	}

	EXIT:
	dbus_message_unref(message);
	if(reply) dbus_message_unref(reply);
	if(pcall) dbus_pending_call_unref(pcall);
	if(cb_data) free(cb_data);
	TRACE_DEBUG(("<%s>: Exit: %d\n", __FUNCTION__, ret));
	return ret;
}

static void CCSP_Message_Bus_Strip(char* str) {
	while(*str) {
		if(*str == 0xa || * str == 0xd) {
			*str = 0;
			break;
		}
		str++;
	}
}











void CCSP_Msg_SleepInMilliSeconds(int milliSecond) {
	struct timeval tm;
	tm.tv_sec = milliSecond/1000;
	tm.tv_usec = (milliSecond%1000)*1000;
	select(0, NULL, NULL, NULL, &tm);
}

int CCSP_Message_Bus_Send_Msg (
		void* bus_handle,
		DBusMessage *message,
		int timeout_seconds,
		DBusMessage **result
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	DBusConnection *conn = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	int ret  = CCSP_Message_Bus_ERROR;

	*result = NULL;  // return value
	dbus_error_init(&err);

	conn = getSendConnection(bus_info);

	if(!conn) {
		dbus_message_unref(message);
		return CCSP_MESSAGE_BUS_CANNOT_CONNECT;
	}

	TRACE_DEBUG(("<%s:%d>: sending to: %s\n", __FUNCTION__, __LINE__, dbus_message_get_destination(message)));
	reply = dbus_connection_send_with_reply_and_block (conn, message, 60000, &err);
	if (!reply) { // -1 is default timeout
		fprintf(stderr, "%s! (%s)\n", err.message, err.name);
		TRACE_ERROR(("<%s:%d>: error sending: %s! (%s) \n", __FUNCTION__, __LINE__, err.message, err.name));
		if( ! strcmp(DBUS_ERROR_DISCONNECTED, err.name)) {
			// try again
			conn = getSendConnection(bus_info);
			reply = dbus_connection_send_with_reply_and_block (conn, message, 60000, &err);

		}
	}
	if(reply) {
		TRACE_DEBUG(("<%s:%d>: reply received \n", __FUNCTION__, __LINE__));
		ret = analyze_reply(message, reply, result);
	} else {
		TRACE_DEBUG(("<%s:%d>: NO reply received \n", __FUNCTION__, __LINE__));
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return ret;
}

int CCSP_Message_Bus_Send_Signal(void* bus_handle, DBusMessage *message) {

	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	DBusConnection *conn = NULL;
	int ret  = CCSP_Message_Bus_ERROR;

    if(!message) return CCSP_ERR_MEMORY_ALLOC_FAIL;

	conn = getSendConnection(bus_info);

	if(!conn) {
		dbus_message_unref(message);
		TRACE_ERROR(("<%s:%d>: NO Send Connection! \n", __FUNCTION__, __LINE__));
		return CCSP_MESSAGE_BUS_CANNOT_CONNECT;
	}

	TRACE_DEBUG(("<%s:%d>: sending to: %s\n", __FUNCTION__, __LINE__, dbus_message_get_destination(message)));
	if(dbus_connection_send(conn, message, 0)) {
		ret = CCSP_Message_Bus_OK;
	}
	TRACE_DEBUG(("<%s:%d>: ret: %d\n", __FUNCTION__, __LINE__, ret));

	dbus_message_unref(message);
	dbus_connection_unref(conn);
	return ret;
}

int CCSP_Message_Bus_Register_Path2(
		void* bus_handle,
		const char* path,
		DBusObjectPathMessageFunction funcptr,
		void * user_data
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

	pthread_mutex_lock(&bus_info->info_mutex);
	bus_info->thread_msg_func = funcptr;
	pthread_mutex_unlock(&bus_info->info_mutex);

	// !!! regardless of what funcptr is,
	// !!! it is always registered with path_message_func for message handling
	return CCSP_Message_Bus_Register_Path_Priv(
			bus_handle,
			path,
			path_message_func,
			bus_handle
	);
}

void CCSP_Message_Bus_Set_Event_Callback (
		void* bus_handle,
		DBusObjectPathMessageFunction   callback,
		void * user_data
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	bus_info->user_data = user_data;
	bus_info->sig_callback = callback;
}

int CCSP_Message_Bus_UnRegister_Event (
		void* bus_handle,
		const char* sender,
		const char* path,
		const char* interface,
		const char* event_name
) {
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	int i = 0;
	DBusConnection *conn = NULL;

	// unregister event
	pthread_mutex_lock(&bus_info->info_mutex);
	if(bus_info->_listen_connection.conn ) {
		conn = bus_info->_listen_connection.conn;
		dbus_connection_ref (conn);
		pthread_mutex_unlock(&bus_info->info_mutex);

		CCSP_Message_Bus_Register_Event_Priv(conn, sender, path, interface, event_name, 0);
		dbus_connection_unref (conn);

		pthread_mutex_lock(&bus_info->info_mutex);
	}
	pthread_mutex_unlock(&bus_info->info_mutex);

	// clear local cache
	char target[512] = {0};
	memset(target, 0, sizeof(target));
	append_event_info(target, sender, path, interface, event_name);

	char candidate[512] = {0};
	pthread_mutex_lock(&bus_info->info_mutex);
	for(i = 0; i < CCSP_MESSAGE_BUS_MAX_FILTER; i++) {
		if(bus_info->filters[i].used ) {
			memset(candidate, 0, sizeof(candidate));
			append_event_info(
					candidate,
					bus_info->filters[i].sender,
					bus_info->filters[i].path,
					bus_info->filters[i].interface,
					bus_info->filters[i].event
			);

			if( strcmp(target, candidate) == 0) {
				if(bus_info->filters[i].sender)    bus_info->freefunc(bus_info->filters[i].sender);
				if(bus_info->filters[i].path)      bus_info->freefunc(bus_info->filters[i].path);
				if(bus_info->filters[i].interface) bus_info->freefunc(bus_info->filters[i].interface);
				if(bus_info->filters[i].event)     bus_info->freefunc(bus_info->filters[i].event);

				bus_info->filters[i].sender        = NULL;
				bus_info->filters[i].path          = NULL;
				bus_info->filters[i].interface     = NULL;
				bus_info->filters[i].event         = NULL;

				bus_info->filters[i].used       = 0;

				break;
			}
		}
	}
	pthread_mutex_unlock(&bus_info->info_mutex);

	if(i == CCSP_MESSAGE_BUS_MAX_FILTER)
		return CCSP_Message_Bus_ERROR;
	else
		return CCSP_Message_Bus_OK;
}

// jlaue: public but not really used - wrong, very much in use
int CCSP_Message_Bus_Register_Event(
		void* bus_handle,
		const char* sender,
		const char* path,
		const char* interface,
		const char* event_name
) {

	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	DBusConnection *conn = NULL;
	int ret = 0;

	pthread_mutex_lock(&bus_info->info_mutex);
	if(bus_info->_listen_connection.conn) {
		conn = bus_info->_listen_connection.conn;
		dbus_connection_ref (conn);
		pthread_mutex_unlock(&bus_info->info_mutex);

		ret = CCSP_Message_Bus_Register_Event_Priv(conn, sender, path, interface, event_name, 1);
		dbus_connection_unref (conn);
		//		if(ret != CCSP_Message_Bus_OK) return ret;

		pthread_mutex_lock(&bus_info->info_mutex);
	}
	pthread_mutex_unlock(&bus_info->info_mutex);

	return CCSP_Message_Save_Register_Event(bus_handle, sender, path, interface, event_name);
}

int CCSP_Message_Bus_Init (
		char *component_id,
		char *config_file,
		void **bus_handle,
		CCSP_MESSAGE_BUS_MALLOC mallocfc,
		CCSP_MESSAGE_BUS_FREE   freefc
) {

	FILE                  *fp              = NULL;
	CCSP_MESSAGE_BUS_INFO *bus_info        = NULL;
	char                  address[256]     = {0};
	int                   count            = 0;

	struct timeval now;
	struct timespec timeout;

	initDebug(component_id);

	if(!mallocfc) mallocfc = malloc;
	if(!freefc) freefc = free ;

	if(!config_file)
		config_file = "ccsp_msg.cfg";

	TRACE_ERROR(("<%s:%d>: enter\n", __FUNCTION__, __LINE__));
	TRACE_DEBUG(("<%s:%d>: debug test\n", __FUNCTION__, __LINE__));

	if ((fp = fopen(config_file, "r")) == NULL) {
		TRACE_ERROR(("<%s>: cannot open %s, try again after a while\n", __FUNCTION__, config_file));
		sleep(2);

		if ((fp = fopen(config_file, "r")) == NULL) {
			TRACE_ERROR(("<%s>: cannot open %s\n", __FUNCTION__, config_file));
			return -1;
		}
	}

	// alloc memory, assign return value
	bus_info =(CCSP_MESSAGE_BUS_INFO*) malloc(sizeof(CCSP_MESSAGE_BUS_INFO));
	if( ! bus_info) {
		TRACE_ERROR(("<%s>: No memory\n", __FUNCTION__));
		return -1;
	}
	memset(bus_info, 0, sizeof(CCSP_MESSAGE_BUS_INFO));
	*bus_handle = bus_info; // return

	// assign malloc and free func
	bus_info->mallocfunc = mallocfc;
	bus_info->freefunc = freefc ;

	// bus name
	if(component_id) {
		snprintf(bus_info->component_id, sizeof(bus_info->component_id), "%s", component_id );
	}

	//    TRACE_DEBUG(("<%s>: component id = '%s'\n", __FUNCTION__, bus_info->component_id));

	// init var, mutex, msg_queue
	pthread_mutex_init(&bus_info->info_mutex, NULL);
	pthread_mutex_lock(&bus_info->info_mutex);
	bus_info->run = 1;
	pthread_mutex_unlock(&bus_info->info_mutex);

	// init the default Dbus threads - this is unnecessary, multiple calls are ok
	if(ccsp_bus_ref_count == 0) dbus_threads_init_default();
	ccsp_bus_ref_count++;

	// Start loop and connect threads to the socket address(es)
	while (fgets(address, sizeof(address), fp)) {
		int size;
		/*assume the first address is our primary connection*/
		CCSP_Message_Bus_Strip(address);  // strip out \cr and \lf
		if(*address == 0) continue;
		if(*address == '#') continue;
		size = sizeof(address);

		TRACE_DEBUG(("<%s:%d>: address: %s\n", __FUNCTION__, __LINE__, address));

		snprintf(
				bus_info->_listen_connection.address,
				size, "%s", address
		);
		bus_info->_listen_connection.bus_info_ptr = (void *)bus_info;
		snprintf(
				bus_info->_send_connection.address,
				size, "%s", address
		);
		bus_info->_send_connection.bus_info_ptr = (void *)bus_info;

		thread_dbus_loop = 0;
		if(component_id) {
			bus_info->_listen_connection.conn = createListenerConnection(bus_info);
			TRACE_DEBUG(("<%s:%d>: after create: address: %s\n", __FUNCTION__, __LINE__, address));
			pthread_create (
					&thread_dbus_loop,
					NULL,
					CCSP_Message_Bus_Loop_Thread,
					(void *)(bus_info)
			);
		}
		break;
	}
	fclose(fp);

	//create a thread to monitor deadlock. Currently Only PandM enabled
	if ( strstr(bus_info->component_id, "com.cisco.spvtg.ccsp.pam" ) != 0 ) {
		deadlock_detection_log =(DEADLOCK_ARRAY*) mallocfc(sizeof(DEADLOCK_ARRAY));
		if ( ! deadlock_detection_log ) {
			TRACE_ERROR(("<%s>: No memory for deadlock log\n", __FUNCTION__));
			return -1;
		}
		memset(deadlock_detection_log, 0, sizeof(DEADLOCK_ARRAY));

		deadlock_detection_enable = 1;
		CcspBaseIf_deadlock_detection_time_normal_seconds = CcspBaseIf_timeout_seconds        + 30 + CcspBaseIf_timeout_protect_plus_seconds;
		CcspBaseIf_deadlock_detection_time_getval_seconds = CcspBaseIf_timeout_getval_seconds + 30 + CcspBaseIf_timeout_protect_plus_seconds;
		pthread_mutex_init(&(deadlock_detection_info.info_mutex), NULL);

		pthread_create(
				&thread_dbus_deadlock_monitor,
				NULL,
				CcspBaseIf_Deadlock_Detection_Thread,
				(void *)bus_info
		);

		TRACE_DEBUG(("<%s>: Deadlock monitor for %s started.\n", __FUNCTION__, bus_info->component_id));
	}

	return 0;
}


void CCSP_Message_Bus_Exit(void *bus_handle) {
	int i;
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	TRACE_ERROR(("<%s>: Enter\n", __FUNCTION__));

	/* Set run to 0, and Trigger to CCSP_Message_Bus_Process_Thread to exit */
	bus_info->run = 0;
	pthread_mutex_lock(&bus_info->info_mutex);
	if(bus_info->_listen_connection.conn)dbus_connection_close(bus_info->_listen_connection.conn);
	pthread_mutex_unlock(&bus_info->info_mutex);

	{ // join all the threads started in init

		char *msg = NULL; int ret = 0;

		TRACE_ERROR(("<%s>: before joins\n", __FUNCTION__));
		if(thread_dbus_loop && (ret = pthread_join(thread_dbus_loop, (void **)&msg)) != 0) {
			TRACE_ERROR(("<%s>: thread connect join returned %d with error %s\n", __FUNCTION__, ret, msg));
		}

		if(thread_dbus_deadlock_monitor && (ret = pthread_join(thread_dbus_deadlock_monitor, (void **)&msg)) != 0) {
			TRACE_ERROR(("<%s>: thread deadlock monitor join returned %d with error %s\n", __FUNCTION__, ret, msg));
		}

		// the loop thread takes a long time to exit
		// so it is skipped and will let OS to clean it up
		/*
        if(thread_dbus_loop && (ret = pthread_join(thread_dbus_loop, (void **)&msg)) != 0) {
            TRACE_ERROR(("<%s>: thread loop join returned %d with error %s\n", __FUNCTION__, ret, msg));
        }
		 */
	}

	if(bus_info->_listen_connection.conn ) {
		//		dbus_connection_close(bus_info->_listen_connection.conn);
		dbus_connection_unref(bus_info->_listen_connection.conn) ;
	}
	if(bus_info->_send_connection.conn ) {
		dbus_connection_close(bus_info->_send_connection.conn);
		dbus_connection_unref(bus_info->_send_connection.conn) ;
	}

	// RTian 5/3/2013    CCSP_Msg_SleepInMilliSeconds(1000);
	pthread_mutex_lock(&bus_info->info_mutex);
	for(i = 0; i < CCSP_MESSAGE_BUS_MAX_FILTER; i++) {
		if(bus_info->filters[i].sender)    bus_info->freefunc(bus_info->filters[i].sender);
		if(bus_info->filters[i].path)      bus_info->freefunc(bus_info->filters[i].path);
		if(bus_info->filters[i].interface) bus_info->freefunc(bus_info->filters[i].interface);
		if(bus_info->filters[i].event)     bus_info->freefunc(bus_info->filters[i].event);
	}

	for(i = 0; i < CCSP_MESSAGE_BUS_MAX_PATH; i++) {
		if(bus_info->path_array[i].path) {
			bus_info->freefunc(bus_info->path_array[i].path);
		}
	}

	if(bus_info->CcspBaseIf_func) bus_info->freefunc(bus_info->CcspBaseIf_func);

	pthread_mutex_unlock(&bus_info->info_mutex);
	pthread_mutex_destroy(&bus_info->info_mutex);

	bus_info->freefunc(bus_info);
	bus_info = NULL;
	ccsp_bus_ref_count--;
	if(ccsp_bus_ref_count == 0) dbus_shutdown();

	//    TRACE_DEBUG(("<%s>: component_id = '%s'\n", __FUNCTION__, bus_info->component_id));

	TRACE_ERROR(("<%s>: Exit\n", __FUNCTION__));
	return;
}
