// The Apple-silicon proof: start the embedded homeserver through the exact
// Swift surface an iPhone app would use, and require its client-server API to
// answer. Not a unit test — the whole composed stack: uniffi FFI, tokio
// runtime, sqlite store, axum listener, iroh endpoint.
import Foundation

let tmp = FileManager.default.temporaryDirectory
    .appendingPathComponent("neutrino-proof-\(UUID().uuidString)").path

let config = NeutrinoConfig(
    bindAddr: "127.0.0.1:8118",
    localpart: "n",
    serverName: nil,
    storageDir: tmp,
    outboundConcurrency: 4,
    trustedNetwork: false,
    lbFederationPort: 8418,
    logDir: nil,
    deliveryReceipts: true
)

print("starting the embedded homeserver…")
let handle = startBle(config: config)

// Poll for readiness the way the Android splash does: server_name appears
// once the identity is resolved, the CS port slightly later.
var name: String? = nil
for _ in 0..<300 {
    if let e = handle.lastError() { fatalError("node refused to start: \(e)") }
    if let n = handle.serverName() { name = n; break }
    Thread.sleep(forTimeInterval: 0.1)
}
guard let serverName = name else { fatalError("no server name within 30s") }
print("server_name: \(serverName)")

var ok = false
for _ in 0..<300 {
    if let url = URL(string: "http://127.0.0.1:8118/_matrix/client/versions"),
       let data = try? Data(contentsOf: url),
       let body = String(data: data, encoding: .utf8),
       body.contains("versions") {
        print("client-server API answers: \(body.prefix(80))")
        ok = true
        break
    }
    Thread.sleep(forTimeInterval: 0.1)
}
guard ok else { fatalError("client-server API never answered") }
print("PROOF: the mesh homeserver runs on Apple silicon")
exit(0)
