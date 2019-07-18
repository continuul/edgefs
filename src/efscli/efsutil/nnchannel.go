package efsutil

/*
#include "ccow.h"
#include "nanomsg/nn.h"
#include "nanomsg/reqrep.h"
*/
import "C"
import "unsafe"

import (
	"os"
)

type nnchannel struct {
	sock C.int
}

// Create a nanomessage NN_REQ connection to specified IPC address
func CreateNanoMsgChannel(path string, rx_tmo_ms int) (*nnchannel, error) {
	ch := &nnchannel{sock: -1}
	sock, errno := C.nn_socket(C.AF_SP, C.NN_REQ)
	if sock < 0 {
		return nil, errno
	}

	tmo := C.int(1000)
	ret, errno := C.nn_setsockopt(sock, C.NN_SOL_SOCKET, C.NN_SNDTIMEO,
		unsafe.Pointer(&tmo), C.sizeof_int)
	if ret < 0 {
		return nil, errno
	}

	tmo = C.int(rx_tmo_ms)
	ret, errno = C.nn_setsockopt(sock, C.NN_SOL_SOCKET, C.NN_RCVTIMEO,
		unsafe.Pointer(&tmo), C.sizeof_int)
	if ret < 0 {
		return nil, errno
	}

	ret, errno = C.nn_setsockopt(sock, C.NN_SOL_SOCKET, C.NN_SNDTIMEO,
		unsafe.Pointer(&tmo), C.sizeof_int)
	if ret < 0 {
		return nil, errno
	}

	ipc := C.CString(path)
	defer C.free(unsafe.Pointer(ipc))

	ret, errno = C.nn_connect(sock, ipc)
	if ret <= 0 {
		return nil, errno
	}
	ch.sock = sock
	return ch, nil
}

// Create IPC connection to ccow-daemon's REQ/REP channel
func CreateCcowdChannel(timeout_ms int) (*nnchannel, error) {
	ipc := "ipc://" + os.Getenv("NEDGE_HOME") + "/var/run/ccowd.ipc"
	return CreateNanoMsgChannel(ipc, timeout_ms)
}

// Send a message to the opened channel
func (ch *nnchannel) Send(msg string) error {
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	ret, errno := C.nn_send(ch.sock, unsafe.Pointer(cmsg), C.strlen(cmsg)+1, 0)
	if ret < 0 {
		return errno
	}
	return nil
}

// Receive a reply from the channel
func (ch *nnchannel) Recv(size uint64) ([]byte, error) {
	buf := make([]byte, size)
	ret, errno := C.nn_recv(ch.sock, unsafe.Pointer(&buf[0]), C.ulong(size), 0)
	if ret < 0 {
		return nil, errno
	}
	return buf, nil
}

// Invoke single REQ/REPL exchange
func (ch *nnchannel) Request(msg string, reply_size uint64) ([]byte, error) {
	ret := ch.Send(msg)
	if ret != nil {
		return nil, ret
	}
	resp, err := ch.Recv(reply_size)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close the channel
func (ch *nnchannel) Close() error {
	ret, errno := C.nn_close(ch.sock)
	if ret < 0 {
		return errno
	}
	return nil
}
