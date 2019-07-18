package app

import "crypto/rand"
import "encoding/hex"

func Set_Request_Id (ctx *Context) error {
    buf := make([]byte, 16)
    _, err := rand.Read(buf)

    if err != nil {
        return err
    }

    id1 := hex.EncodeToString(buf[0:8])
    id2 := hex.EncodeToString(buf[8:16])

    ctx.Set("x-amz-request-id", id1);
    ctx.Set("x-amz-id-2", id2);

    ctx.id = id1

    return nil
}
