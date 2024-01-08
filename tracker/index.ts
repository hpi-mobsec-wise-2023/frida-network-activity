import assert from "node:assert";

// I found this first: https://github.com/iddoeldor/frida-snippets#socket-activity
// After successfully setting up Frida with Typescript, I wrote the code below myself and
// played around with it to understand what it does.

assert(Java.available)

function parsePeer(fdPointer: NativePointer, addressLengthPointer: NativePointer | null, addressPointer: NativePointer | null): { fd: number, type: SocketType, address: string } | null {
    const fd = fdPointer.toInt32()
    const fdtype = Socket.type(fd)
    if (fdtype === null || ['unix:stream', 'unix:dgram'].includes(fdtype)) {
        return null
    }
    // There is also an address associated with the socket if `connect` has been called.
    const peerAddress = Socket.peerAddress(fd)
    if (peerAddress !== null) {
        const peerIpAddress = peerAddress as TcpEndpointAddress
        if (!peerIpAddress.ip.startsWith('::ffff:')) {
            console.log(`Real IPv6 addresses are not supported!`)
            return null
        }
        return {
            fd: fd,
            type: fdtype,
            address: `${peerIpAddress.ip.substring(7)}:${peerIpAddress.port}`,
        }
    }
    if (addressLengthPointer !== null && addressPointer !== null) {
        const addressLength = addressLengthPointer.toInt32()
        const address = addressPointer.readByteArray(addressLength)
        if (address === null) {
            console.log(`Could not read sockaddr struct!`)
            return null
        }
        const dataView = new DataView(address)
        const sa_family = dataView.getUint8(0)
        if (sa_family === 10) {
            // AF_INET6
            //            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            // 00000000  0a 00 01 bb 00 00 00 00 00 00 00 00 00 00 00 00  ................
            // 00000010  00 00 ff ff b9 46 2a 29 00 00 00 00              .....F*)....
            const port = dataView.getUint16(2, false)
            const ipBytes = []
            for (let i = 0; i < 16; i++)  {
                ipBytes.push(dataView.getUint8(8 + i))
            }
            for (let i = 0; i < 10; i++) {
                if (ipBytes[i] !== 0) {
                    console.log(`Real IPv6 addresses are not supported!`)
                    return null
                }
            }
            for (let i = 10; i < 12; i++) {
                if (ipBytes[i] !== 255) {
                    console.log(`Real IPv6 addresses are not supported!`)
                    return null
                }
            }
            const address = ipBytes.slice(12).join('.')
            return {
                fd: fd,
                type: fdtype,
                address: `${address}:${port}`,
            }
        } else if (sa_family === 2) {
            // AF_INET
            console.log(`Real IPv4 not implemented yet!`)
            return null
        } else {
            console.log(`Unrecognized family!`)
            return null
        }
    } else {
        console.log(`Peer address is null and not enough other information given!`)
        return null
    }
}

function printStackTrace() {
    if (shouldPrintStackTrace && !quiet) {
        Java.perform(() => {
            const thread = Java.use('java.lang.Thread').$new()
            const stackTrace = thread.currentThread().getStackTrace()
            console.log(`\t${stackTrace.join('\n\t')}`)
        })
    }
}

function saveSent(peer: string, bytesSent: number) {
    const statistic = {
        sent: bytesSent,
        received: 0,
    }
    if (networkStatistics.has(peer)) {
        const existingStatistic = networkStatistics.get(peer)
        assert(existingStatistic !== undefined)
        statistic.sent = bytesSent + existingStatistic.sent
        statistic.received = existingStatistic.received
    }
    networkStatistics.set(peer, statistic)
}

function saveReceived(peer: string, bytesReceived: number) {
    const statistic = {
        sent: 0,
        received: bytesReceived,
    }
    if (networkStatistics.has(peer)) {
        const existingStatistic = networkStatistics.get(peer)
        assert(existingStatistic !== undefined)
        statistic.sent = existingStatistic.sent
        statistic.received = bytesReceived + existingStatistic.received
    }
    networkStatistics.set(peer, statistic)
}

function printNetworkStatistic() {
    log(`Network statistics:`)
    networkStatistics.forEach((statistic, peer) => {
        log(`\t${peer}: sent=${statistic.sent} received=${statistic.received}`)
    })
}
setInterval(printNetworkStatistic, 30000)

function log(message: string) {
    if (!quiet) {
        console.log(message)
    }
}

const networkStatistics = new Map<string, { sent: number, received: number }>
const shouldPrintStackTrace = false
const quiet = false

// There are multiple functions regarding sending network traffic: send, sendmsg, sendmmsg, sendto, and probably more.
// Also see here: https://manpages.ubuntu.com/manpages/mantic/en/man2/send.2freebsd.html
// I executed `frida-trace -U -f ch.protonmail.android -i 'libc.so!{function}'` and clicked some buttons in the app.
// It seems that the app uses only sendto and sendmsg, so those will be the functions we track here.
// Furthermore, it seems like sendto only uses sendmsg under the hood: After every sendto call with a payload length,
// there is a call to sendmsg and which reports the same number of bytes sent in the return value.
// Therefore, we are only tracking sendto here.
const sendtoExport = Module.getExportByName('libc.so', 'sendto')
assert(sendtoExport !== null)
Interceptor.attach(
    sendtoExport,
    {
        onEnter(args) {
            this.peer = parsePeer(args[0], args[5], args[4])
            if (this.peer === null) {
                return
            }
            const length = args[2].toInt32()
            log(`sendto (enter): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, wants to send ${length} bytes`)
            printStackTrace()
        },
        onLeave(retval) {
            if (this.peer === null) {
                return
            }
            const sentBytes = retval.toInt32()
            saveSent(this.peer.address, sentBytes)
            log(`sendto (leave): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, has sent ${sentBytes} bytes`)
        }
    }
)

// There are multiple functions regarding sending network traffic: recv, recvmsg, recvmmsg, recvfrom, and probably more.
// Also see here: https://manpages.ubuntu.com/manpages/mantic/en/man2/recv.2freebsd.html
// I executed `frida-trace -U -f ch.protonmail.android -i 'libc.so!{function}'` and clicked some buttons in the app.
// It seems that the app uses only recvfrom and recvmsg, so those will be the functions we track here.
// Further investigations showed, that recvmsg is only used for the socket type `unix:stream`.
// Therefore, we are only tracking sendto here.
const recvfromExport = Module.getExportByName('libc.so', 'recvfrom')
assert(recvfromExport !== null)
Interceptor.attach(
    recvfromExport,
    {
        onEnter(args) {
            this.peer = parsePeer(args[0], args[5], args[4])
            if (this.peer === null) {
                return
            }
            const length = args[2].toInt32()
            log(`recvfrom (enter): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, provides receiving buffer with ${length} bytes`)
            printStackTrace()
        },
        onLeave(retval) {
            if (this.peer === null) {
                return
            }
            const receivedBytes = retval.toInt32()
            saveReceived(this.peer.address, receivedBytes)
            log(`recvfrom (leave): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, has received ${receivedBytes} bytes`)
        }
    }
)

// This should also capture peers where no connection could be established.
const socketExport = Module.getExportByName('libc.so', 'socket')
assert(socketExport !== null)
Interceptor.attach(
    socketExport,
    {
        onEnter(args) {
            const domain = args[0].toInt32()
            const type = args[1].toInt32()
            const protocol = args[2].toInt32()
            if (domain === 1) {
                // This seems to be a unix socket.
                this.irrelevant = true
                return
            }
            log(`socket (enter): domain=${domain}, type=${type}, protocol=${protocol}`)
            printStackTrace()
        },
        onLeave(retval) {
            if (this.irrelevant) {
                return
            }
            const fd = retval.toInt32()
            const fdtype = Socket.type(fd)
            log(`socket (leave): fdtype=${fdtype}, fd=${fd}`)
        }
    }
)

const connectExport = Module.getExportByName('libc.so', 'connect')
assert(connectExport !== null)
Interceptor.attach(
    connectExport,
    {
        onEnter(args) {
            this.peer = parsePeer(args[0], args[2], args[1])
            if (this.peer === null) {
                return
            }
            log(`connect (enter): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}`)
            saveSent(this.peer.address, 0)
            printStackTrace()
        },
        onLeave(retval) {
            if (this.peer === null) {
                return
            }
            // TODO: This seems to be always -1 although the socket is successfully used later.
            if (retval.toInt32() === 0) {
                log(`connect (leave): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, success`)
            } else {
                log(`connect (leave): fdtype=${this.peer.type}, fd=${this.peer.fd}, peer=${this.peer.address}, failed`)
            }
        }
    }
)

// TODO: I wanted to print network statistics if the script is terminated.
//  However, when loaded with Frida, I get `ReferenceError: 'process' is not defined`
// process.on('SIGTERM', () => {
//     console.log('signal: SIGTERM')
//     process.exit(1)
// })
//
// process.on('SIGQUIT', () => {
//     console.log('signal: SIGQUIT')
//     process.exit(1)
// })
//
// process.on('SIGHUP', () => {
//     console.log('signal: SIGHUP')
//     process.exit(1)
// })
//
// process.on('SIGINT', () => {
//     console.log('signal: SIGINT')
//     process.exit(1)
// })
