// listener.go — UDS accept loop.
// Listens on the socket path from config (default: /tmp/acf.sock).
// Spawns one goroutine per accepted connection.
// Each connection: read frame → dispatch to pipeline → write response frame.
// Invalid HMAC or reused nonce drops the connection immediately.
package transport
