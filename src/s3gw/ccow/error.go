package ccow

/*
#include <errno.h>
*/
import "C"
import "fmt"

type Errno struct {
    message string
    code int
}

func (e Errno) Error() string {
    return fmt.Sprintf("%s %d", e.message, e.code)
}

func Error(msg string, ret C.int) Errno {
    return Errno{msg, int(-ret)}
}

func Not_Found(err error) bool {
    if e, ok := err.(Errno); ok {
        if e.code == C.ENOENT {
            return true
        }
    }
    return false
}
