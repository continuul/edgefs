package ccow

/*
#include "ccow.h"
*/
import "C"
import "unsafe"
import "strconv"
import "strings"
import "encoding/hex"

type Meta map[string]interface{}

/* The original uint512_dump, uint256_dump etc do a weird trick of splitting
   their respective uintN-s into 8-byte chunks in big-endian order, but then
   reading individual 8-byte (uint64) values as host-endian which means little
   ending on x86_64. This is probably wrong, but it has to be done like that
   to keep compatibility with the data created from JS code.

   In particular, ccow-name-hash-id is UINT512 but the name of the actual
   bucket is exactly uint512_dump(ccow-name-hash-id). */

func uintN_dump(buf []byte) string {
    n := len(buf)
    tmp := make([]byte, n, n)

    if n % 8 != 0 {
        return strings.ToUpper(hex.EncodeToString(buf))
    }

    for i := 0; i < n; i += 8 {
        for j := 0; j < 8; j++ {
            tmp[i + j] = buf[i + 8 - j - 1]
        }
    }

    return strings.ToUpper(hex.EncodeToString(tmp))
}

func (attrs *Meta) String (key string) string {
    if val, ok := (*attrs)[key]; ok {
        if ret, ok := val.(string); ok {
            return ret
        }
        if bytes, ok := val.([]byte); ok {
            return uintN_dump(bytes)
        }
        if num, ok := val.(uint64); ok {
            return strconv.FormatUint(num, 10)
        }
        if num, ok := val.(int64); ok {
            return strconv.FormatInt(num, 10)
        }
        if num, ok := val.(uint); ok {
            return strconv.FormatUint(uint64(num), 10)
        }
        if num, ok := val.(int); ok {
            return strconv.FormatInt(int64(num), 10)
        }
    }

    return ""
}

func (attrs *Meta) Uint (key string) uint {
    if val, ok := (*attrs)[key]; ok {
        if num, ok := val.(uint); ok {
            return num
        }
        if num, ok := val.(int); ok {
            return uint(num)
        }
    }

    return 0
}

func (attrs *Meta) Uint64 (key string) uint64 {
    if val, ok := (*attrs)[key]; ok {
        if num, ok := val.(uint64); ok {
            return num
        }
        if num, ok := val.(uint); ok {
            return uint64(num)
        }
        if num, ok := val.(int); ok {
            return uint64(num)
        }
    }

    return 0
}

func lookup_to_meta (iter C.ccow_lookup_t) *Meta {
    var out = Meta { }
	var kv *C.struct_ccow_metadata_kv
	mask := C.int(C.CCOW_MDTYPE_METADATA | C.CCOW_MDTYPE_CUSTOM | C.CCOW_MDTYPE_VERSIONS)

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter, mask, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

        key := C.GoString(kv.key)

		if kv._type == C.CCOW_KVTYPE_INT8 {
			out[key] = int(*(*C.char)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_UINT8 {
			out[key] = uint(*(*C.uchar)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_INT16 {
			out[key] = int(*(*C.short)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_UINT16 {
			out[key] = uint(*(*C.ushort)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_INT32 {
			out[key] = int(*(*C.int)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_UINT32 {
			out[key] = uint(*(*C.uint)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_INT64 {
			out[key] = int64(*(*C.int64_t)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_UINT64 {
			out[key] = uint64(*(*C.uint64_t)(kv.value))
		} else if kv._type == C.CCOW_KVTYPE_RAW {
			//out[key] = C.GoBytes((unsafe.Pointer)(kv.value), (C.int)(kv.value_size))
            out[key] = C.GoStringN((*C.char)(kv.value), (C.int)(kv.value_size))
		} else if kv._type == C.CCOW_KVTYPE_UINT128 {
			out[key] = C.GoBytes((unsafe.Pointer)(kv.value), 16)
		} else if kv._type == C.CCOW_KVTYPE_UINT512 {
			out[key] = C.GoBytes((unsafe.Pointer)(kv.value), 64)
		} else if kv._type == C.CCOW_KVTYPE_STR {
            if C.int(kv.value_size) > 1 {
                out[key] = C.GoStringN((*C.char)(kv.value), (C.int)(kv.value_size) - 1)
            } else {
                out[key] = ""
            }
		} else {
            continue
        }
	}

    return &out
}
