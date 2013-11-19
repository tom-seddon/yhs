#ifndef YHS_H_D6057315455C40F9B45D68049C1EB35E
#define YHS_H_D6057315455C40F9B45D68049C1EB35E

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// yhs - yocto HTTP server
// -----------------------
//
// `yocto' is (at the time of writing) the smallest SI prefix. It is
// very small.
//
// `yocto' refers to the server's feature set, not the size of the code.
// Though there's not THAT much to trawl through.
//
// THIS IS NOT FOR PRODUCTION USE. It's designed for use during development.
//
// yhs was written by Tom Seddon <yhs@tomseddon.plus.com>.
//
// yhs is in the public domain.
//
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdarg.h>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
#define YHS_EXTERN extern "C"
#else//__cplusplus
#define YHS_EXTERN
#endif//__cplusplus

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef _MSC_VER
#define YHS_PRINTF_LIKE(A,B)
#else
#define YHS_PRINTF_LIKE(A,B) __attribute__((format(printf,(A),(B))))
#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Types
//

struct yhsServer;
typedef struct yhsServer yhsServer;

struct yhsRequest;
typedef struct yhsRequest yhsRequest;

struct yhsHandler;
typedef struct yhsHandler yhsHandler;

// yes, it's another bool type...
//
// this is purely for documentation purposes. yhsBool = int, and that's a
// promise.
typedef int yhsBool;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Get SHA1 hash of a buffer.
//
// IN
//
// buffer,len - the buffer
//
// output - the 20 bytes to fill in with the SHA1.
//
// NOTES
//
// - SHA1 hashing is not really part of a web server, but web sockets
//   uses it, and I needed something like it for my test program, so it
//   sort of came along for the ride.
//
//   If you don't need it, don't call it.
YHS_EXTERN void yhs_sha1(unsigned char output[20],const void *buffer,unsigned len);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// HTTP methods.
//
// These are used both as bitflags and individual values.
enum yhsMethod
{
	// OTHER represents any method(s) not listed here.
	YHS_METHOD_OTHER=1,

	//
	YHS_METHOD_GET=2,
	YHS_METHOD_PUT=4,
	YHS_METHOD_POST=8,
	YHS_METHOD_HEAD=16,

	// OK, sure, so "websocket" isn't really a method.
	YHS_METHOD_WEBSOCKET=32,
};
typedef enum yhsMethod yhsMethod;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Path handler function type.
//
// IN
//
// re - the response object (you'll need this for sending data back)
//
// context - the context pointer supplied when `yhs_add_res_path_handler' was
//           called
YHS_EXTERN typedef void (*yhsResPathHandlerFn)(yhsRequest *re);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Server management
//

// Create new server that will serve files on the given port.
//
// IN
//
// port - the port to serve on.
//
// OUT
//
// yhsServer * - pointer to the new server object.
//
// NOTES
//
// - The server creates its socket using SO_REUSEADDR, so that you don't
//   have to wait for the socket timeout when restarting your program.
//   This does mean that you can create multiple servers in your
//   program, all serving from the same place, and it won't complain.
//   That is not a supported use case.
//
// - Port 80 is a reasonable choice.
//
// - The server object is allocated using `calloc'
YHS_EXTERN yhsServer *yhs_new_server(int port);

// Set server's name. The server's name appears in the TOC and
// error pages.
//
// IN
//
// server - server to update
//
// name - name to set
//
// NOTES:
//
// - There is a max length for the name.
YHS_EXTERN void yhs_set_server_name(yhsServer *server,const char *name);

// Delete a server, freeing the resources it's using.
//
// IN
//
// server - the server to delete.
YHS_EXTERN void yhs_delete_server(yhsServer *server);

// Update the given server. Incoming requests will be fielded, and
// handler functions called as appropriate.
//
// IN
//
// server - the server to update.
//
// OUT
//
// int - 1 if any requests were serviced, 0 if not. 
//
// NOTES
//
// - `yhs_update' will keep fielding requests until there are none
//   incoming. There's no specific limit to how many requests it will
//   handle and how long this will take. However, if there's nothing to
//   do, it should return pretty quickly.
YHS_EXTERN yhsBool yhs_update(yhsServer *server);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Server logging stuff
//

// Log categories.
enum yhsLogCategory
{
	YHS_LOG_DEBUG,
	YHS_LOG_INFO,
	YHS_LOG_ERROR,
	
	YHS_LOG_ENDVALUE,
};
typedef enum yhsLogCategory yhsLogCategory;

// Log handler function type.
//
// IN
//
// category - the log category
//
// message - the message to print
//
// context - value supplied to yhs_set_server_log_callback
YHS_EXTERN typedef void (*yhsLogFn)(yhsLogCategory category,const char *message,void *context);

// Set callback for log messages printed by the given server.
//
// IN
//
// server - server to set callback for.
//
// fn,context - yhsLogFn to call, and the context to call it with.
//
// NOTES
//
// - the default callback prints error messages to stderr, and info and
//   debug messages to stdout.
YHS_EXTERN void yhs_set_server_log_callback(yhsServer *server,yhsLogFn fn,void *context);

// Enable or disable a given log type for the server.
//
// NOTES
//
// - initial states are:
//
//   - YHS_LOG_DEBUG - disabled
//   - YHS_LOG_INFO - disabled
//   - YHS_LOG_ERROR - enabled
YHS_EXTERN void yhs_set_server_log_enabled(yhsServer *server,yhsLogCategory category,yhsBool enabled);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Response management
//

// Begin response to a request, specifying the Content-Type. Once the
// response has been started, you can use `yhs_text*' or `yhs_data' to
// send more data.
//
// IN
//
// response - the response object
//
// type - the Content-Type (e.g., "text/html")
YHS_EXTERN void yhs_begin_data_response(yhsRequest *req,const char *type);

// Send response text verbatim.
//
// IN
//
// response - the response object
//
// fmt,... - the usual format string thing fmt,v - the usual format string thing
// text - text to send
//
// NOTES
//
// - Space for the expansion is limited; see the MAX_TEXT_LEN constant.
//
// - Response data is automatically discarded when processing a HEAD request.
//
// - There is no difference between "text" and "data", except for the API. In
//   particular, newline translation is not performed.
YHS_EXTERN void yhs_textf(yhsRequest *req,const char *fmt,...) YHS_PRINTF_LIKE(2,3);
YHS_EXTERN void yhs_textv(yhsRequest *req,const char *fmt,va_list v);
YHS_EXTERN void yhs_text(yhsRequest *req,const char *text);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Send response text, optionally with HTML special characters escaped, and
// optionally with \n replaced with <BR>.
//
// Print "\a+" to switch escaping on, and "\a-" to switch it off.
//
// Print "\b+" to switch <BR> translation on, and "\b-" to switch it off.
//
// IN
//
// response - the response object
//
// fmt,... - the usual format string thing
// fmt,v - the usual format string thing
// text - text to send
//
// NOTES
//
// - Space for the format string expansion is limited; see the MAX_TEXT_LEN
//   constant.
//
// - I'm not sure "html" is the best term for it.
//
// - Response data is automatically discarded when processing a HEAD request.
//
YHS_EXTERN void yhs_html_textf(yhsRequest *req,const char *fmt,...) YHS_PRINTF_LIKE(3,4);
YHS_EXTERN void yhs_html_textv(yhsRequest *req,const char *fmt,va_list v);
YHS_EXTERN void yhs_html_text(yhsRequest *req,const char *text);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Send response data.
//
// IN
//
// response - the response object
//
// data - pointer to data to send
//
// data_size - number of chars to send
YHS_EXTERN void yhs_data(yhsRequest *req,const void *data,size_t data_size);

// Send response data.
//
// IN
//
// response - the response object
//
// value - the byte to send
YHS_EXTERN void yhs_data_byte(yhsRequest *req,unsigned char value);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Begin sending an image.
//
// IN
//
// response - the response object
//
// width,height - dimensions of the image
//
// ncomp - number of components in the image; 3 = RGB, 4 = RGBA.
//
// NOTES
//
// - The image encoding is not very efficient.
//
// - Once you have started sending an image, you are committed to it, and
//   must send every pixel.
//
// - `ncomp' is supposed to mirror the stb_image behaviour a bit, but it's
//   not really very general.
YHS_EXTERN void yhs_begin_image_response(yhsRequest *req,int width,int height,int ncomp);

// Send the next pixel in an image response.
//
// IN
//
// response - the response object
//
// r,g,b,a - red, green, blue and alpha values for the pixel, each 0-255.
//           (alpha is ignored if ncomp was 3.)
//
// NOTES
//
// - Response data is automatically discarded when processing a HEAD request.
YHS_EXTERN void yhs_pixel(yhsRequest *respones,int r,int g,int b,int a);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Respond with the given status, and include an HTML error page for it.
//
// IN
//
// response - the response object
//
// status_line - the status line, as per the HTTP spec, without the leading
//               "HTTP/1.1 ". e.g., "200 OK".
//
// elaboration - a more detailed explanation for the error, included in the HTML
//               error page.
//
YHS_EXTERN void yhs_error_response(yhsRequest *req,const char *status_line);
YHS_EXTERN void yhs_verbose_error_response(yhsRequest *req,const char *status_line,const char *elaboration);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Respond with a 303 See Other, pointing the client to the given
// destination.
//
// IN
//
// response - the response object
//
// destination - the URL the client should go to
//
// NOTES
//
// - "Unless the request method was HEAD, the entity of the response
//   SHOULD contain a short hypertext note with a hyperlink to the new
//   URI(s)." - so perhaps it should do that? But it doesn't.
YHS_EXTERN void yhs_see_other_response(yhsRequest *req,const char *destination);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Respond by opening a websocket connection. The method must be
// YHS_METHOD_WEBSOCKET.
// 
// IN
//
// re - the response object
//
// protocol - the protocol to use
//
YHS_EXTERN void yhs_accept_websocket(yhsRequest *re,const char *protocol);

// if there was an error, the web socket is closed.
YHS_EXTERN yhsBool yhs_is_websocket_open(yhsRequest *re);

// the recv succeeds if there is a frame waiting to be received. if the recv
// succeeds, use yhs_recv_websocket_data to get the actual data, then use
// end_recv_websocket_frame to finish off receiving it.
YHS_EXTERN yhsBool yhs_begin_recv_websocket_frame(yhsRequest *re,int *is_text);
YHS_EXTERN void yhs_end_recv_websocket_frame(yhsRequest *re);

// receives up to buf_size bytes, storing them at buf.
//
// returns 1 on success. either bytes were received (and *n is the number of
// bytes received), or the end of the frame was reached (and *n is set to zero).
// if bytes were received, you can't tell that the end of the frame was reached
// other than by trying again.
//
// returns 0 on failure.
YHS_EXTERN yhsBool yhs_recv_websocket_data(yhsRequest *re,void *buf,size_t buf_size,size_t *n);

// send web socket data.
//
// between the begin and end call, use the various yhs_text/yhs_data functions
// to send data. (even yhs_html_text works.) the output is added to the frame,
// and off it goes.
//
// yhs will fragment the frame at its discretion.
YHS_EXTERN void yhs_begin_send_websocket_frame(yhsRequest *re,int is_text);
YHS_EXTERN void yhs_end_send_websocket_frame(yhsRequest *re);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Response header fields
//
// Once a response has been started using the yhs_xxx_response or
// yhs_accept_websocket functions, but before any data has been sent, further
// fields can be added to the header.
//

// Add a field to the response header.
//
// IN
//
// name - header field name
//
// value - header field value
//
// NOTES
//
// - the data is sent verbatim, so don't send anything invalid.
//
// - don't set the Content-Type field; the yhs_xxx_response functions do that
//   already.
YHS_EXTERN void yhs_header_field(yhsRequest *req,const char *name,const char *value);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Deferred response
//

// Opt to defer a response. 
//
// IN
//
// re - the response to put off until later
//
// yhsRequest ** - points to pointer to first request in the chain. The new
//                 response is added to the head.
//
// OUT
//
// int - flag indicating success or failure - yhs_defer_response will fail if
//       there isn't room to allocate the deferred response.
// 
// NOTES
//
// - Deferred responses use up resources until they are actually dealt with.
//
YHS_EXTERN yhsBool yhs_defer_response(yhsRequest *re,yhsRequest **chain);

// Method of iteration:
//
// yhsRequest **ptr=&whatever;//whatever was passed in to yhs_defer_response
// while(*ptr) {
//     if(done)
//         yhs_end_deferred_response(ptr);
//     else
//         yhs_next_request_ptr(ptr);

YHS_EXTERN void yhs_next_request_ptr(yhsRequest **re_ptr);
YHS_EXTERN void yhs_end_deferred_response(yhsRequest **re_ptr);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Getting request details

// Retrieve the path the request is for.
//
// IN
//
// re - the request
//
// OUT
//
// const char * - the path
YHS_EXTERN const char *yhs_get_path(yhsRequest *re);

// Retrieve the request method.
//
// IN
//
// re - the request
//
// OUT
//
// yhsMethod - the method. (yhsMethod has values like a bit field, but only one
//             of the values will be returned here.)
//
// NOTES
//
// - YHS_METHOD_OTHER is returned if it wasn't one of the recognised ones (use
//   yhs_get_method_str to see exactly what it was).
YHS_EXTERN yhsMethod yhs_get_method(yhsRequest *re);

// Retrieve the request method as a string.
//
// IN
//
// re - the request
//
// OUT
//
// const char * - the method.
YHS_EXTERN const char *yhs_get_method_str(yhsRequest *re);

// Find the value, if any, for a header field in the request.
//
// IN
//
// re - the request
//
// name - the name of the header field to search for
//
// last_result - result of previous search, if any, or NULL if no previous
//               search (see below)
//
// OUT
//
// const char * - the field's value, or NULL if field not found
//
// NOTES
//
// - use last_result to find all values for a given field. (The server doesn't
//   automatically coalesce header fields.) Pass in the result from a previous
//   invocation of yhs_find_header_field.
//
//   e.g.,
//
// <pre>
//   char *value=0;
//   while(value=yhs_find_header_field(re,"Key",value));
//       printf("%s\n",value);
// </pre>
YHS_EXTERN const char *yhs_find_header_field(yhsRequest *re,const char *name,const char *last_result);

// Get the context pointer associated with the handler that was used to service
// the request.
YHS_EXTERN void *yhs_get_handler_context(yhsRequest *re);

// Get resource path associated with the handler used to service the request.
YHS_EXTERN const char *yhs_get_handler_path(yhsRequest *re);

YHS_EXTERN const char *yhs_get_path_handler_relative(yhsRequest *re);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Getting content data
//

// Get content details.
//
// IN
//
// req - request object
//
// type - pointer to const char * to fill in with pointer to MIME type of
//        content (this could be NULL if the client didn't say)
//
// length - pointer to int to fill in with length of content
//
// OUT
//
// bool - 1 if there is some content (and *type and *length are filled in),
//        0 if not.
//
// NOTES
//
// - type and length may be NULL, if you don't care.
//
// - this function doesn't do anything magic. It just calls
//   yhs_find_header_field and validates the result.
YHS_EXTERN yhsBool yhs_get_content_details(yhsRequest *req,const char **type,int *length);

// Get bytes of content data.
//
// IN
//
// response - the response object
//
// n - maximum number of bytes to fetch
//
// buf - buffer to store data in
//
// OUT
//
// int - 1 if as many bytes were retrieved as requested, 0 if not.
//
// NOTES
//
// - you can fetch the content in pieces.
YHS_EXTERN yhsBool yhs_get_content(yhsRequest *req,int n,char *buf);

// Access control data from a POSTed form.
//
// IN
//
// response - the response object
//
// args - the yhsResPathHandlerArgs passed in to your handler
//
// OUT
//
// int - 1 if successful, 0 if not.
//
// NOTES
//
// - yhs_read_form_content eats the posted content, so you can't use
//   yhs_get_content.
//
// - yhs_read_form_content allocates memory.
YHS_EXTERN yhsBool yhs_read_form_content(yhsRequest *req);

// Retrieve value for a control.
//
// IN
//
// response - the response object
//
// control_name - name of control, as per its name attribute
//
// OUT
//
// const char * - pointer to the control's value, or NULL if no
//                such control
//
// NOTES
//
// - the return value points into memory that will be freed when your
//   handler returns.
YHS_EXTERN const char *yhs_find_control_value(yhsRequest *req,const char *control_name);

// Get number of controls in form content.
//
// IN
//
// response - the response object
//
// OUT
//
// size_t - number of controls
YHS_EXTERN size_t yhs_get_num_controls(yhsRequest *req);

// Get details about controls in form content.
//
// IN
//
// response - the response object
//
// index - control index, >=0 and <yhs_get_num_controls(response)
//
// NOTES
//
// - the return value points into memory that will be freed when your
//   handler returns.
YHS_EXTERN const char *yhs_get_control_name(yhsRequest *req,size_t index);
YHS_EXTERN const char *yhs_get_control_value(yhsRequest *req,size_t index);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Path handler management
//

// Add a handler for a particular path.
//
// IN
//
// server - the server to add the handler to
//
// res_path - path to handle
//
// handler_fn - function to handle it
//
// context - the usual context pointer thing
//
// OUT
//
// yhsHandler * - a token representing the handler
//
// NOTES
//
// - If the path ends in something other than a '/', the handler is assumed
//   to be for a particular "file" and will be called only for URIs that
//   seem to correspond to that name.
//
// - If the path ends in a '/', the handler is assumed to be for a particular
//   "folder". It will be called for URIs that mention that folder and
//   end with a '/', and for URIs that mention a file in that folder, if there's
//   no specific handler for that "file".
//
// - The matching isn't recursive, which is a bit crap.
//
// - `yhs_add_res_path_handler' allocates memory.
YHS_EXTERN yhsHandler *yhs_add_res_path_handler(yhsServer *server,const char *res_path,yhsResPathHandlerFn handler_fn,void *context);

// Add the given handler to the TOC.
//
// IN
//
// handler - the handler to add to the TOC
//
// OUT
//
// yhsHandler * - the value of the handler parameter
//
// NOTES
//
// - if description is NULL, the description is formed from the path
YHS_EXTERN yhsHandler *yhs_add_to_toc(yhsHandler *handler);

// Set the description for the given handler. If a description is set, it is
// used when displaying the TOC.
//
// IN
//
// description - the description to set
//
// handler - the handler
//
// OUT
//
// yhsHandler * - the value of the handler parameter
//
// NOTES
//
// - having the object as the last parameter is kind of inconsistent, compared
//   to everything else; it's supposed to be easier to read if multiple calls
//   are chained.
//
// - `yhs_set_handler_description' allocates memory.
YHS_EXTERN yhsHandler *yhs_set_handler_description(const char *description,yhsHandler *handler);

// Set the valid methods for the given handler. The server will ignore this
// handler when processing other methods.
//
// IN
//
// valid_methods - combination of yhsMethod values, indicating valid methods
//
// handler - the handler
//
// OUT
//
// yhsHandler * - the value of the handler parameter
//
// NOTES
//
// - having the object as the last parameter is kind of inconsistent, compared
//   to everything else; it's supposed to be easier to read if multiple calls
//   are chained.
//
// - if valid_methods includes YHS_METHOD_GET, YHS_METHOD_HEAD is automatically
//   assumed.
//
// - the default valid methods are YHS_METHOD_GET|YHS_METHOD_HEAD.
YHS_EXTERN yhsHandler *yhs_set_valid_methods(unsigned valid_methods,yhsHandler *handler);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// A handler that serves files in response to GET/HEAD. Supply the local path on
// the server (e.g., "/users/fred/html/", or "C:\\temp\\web") as a string as the
// context pointer.
//
// The requested path will be made relative to the resource path, and that
// relative path appended to the local path to find the path to a local
// resource.
//
// If the path is a folder, the handler will supply a basic files listing in the
// form of an HTML page.
//
// If the path is a file, the handler will send the file's contents, with the
// MIME type being inferred from the extension.
//
// IN
//
// re - the request
//
// NOTES
//
// - this is not intended to be amazingly clever, nor comprehensive, nor
//   especially secure. You're sort of expected to only have one or two of these
//   folders, for common resources such as PNGs or Javascript files.
YHS_EXTERN void yhs_file_server_handler(yhsRequest *re);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Run unit tests.
//
// The tests are performed using `assert'.
YHS_EXTERN void yhs_run_unit_tests(void);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#endif//YHS_H_D6057315455C40F9B45D68049C1EB35E
