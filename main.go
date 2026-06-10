package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf kestrel.c -- -I. -I/usr/include -D__TARGET_ARCH_x86

type QueryEvent struct {
    Pid   uint32
    _     uint32 // padding to align ts to 8 bytes
    Ts    uint64
    Comm  [16]byte
    Query [256]byte
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close()

    kp, err := link.Kprobe("tcp_sendmsg", objs.KestrelTcpSendmsg, nil)
    if err != nil {
        log.Fatalf("opening kprobe: %v", err)
    }
    defer kp.Close()

    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        log.Fatalf("opening ringbuf: %v", err)
    }
    defer rd.Close()

    fmt.Println("🦅 Kestrel is watching Postgres on :5433")
    fmt.Println("────────────────────────────────────────")

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-stop
        rd.Close()
    }()

    var e QueryEvent
    for {
        rec, err := rd.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                return
            }
            continue
        }
        if err := binary.Read(bytes.NewReader(rec.RawSample),
            binary.LittleEndian, &e); err != nil {
            continue
        }
        fmt.Printf("[%s] pid=%-6d app=%-12s %s\n",
            time.Now().Format("15:04:05"),
            e.Pid,
            cstr(e.Comm[:]),
            cstr(e.Query[:]),
        )
    }
}

func cstr(b []byte) string {
    if n := bytes.IndexByte(b, 0); n >= 0 {
        return string(b[:n])
    }
    return string(b)
}