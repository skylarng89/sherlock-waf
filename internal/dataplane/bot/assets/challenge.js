/* Sherlock proof-of-work solver. Self-contained: no external scripts, no eval. */
(function () {
  'use strict'
  var root = document.getElementById('sherlock-challenge')
  if (!root) return
  var token = root.getAttribute('data-token')
  var digits = parseInt(root.getAttribute('data-difficulty'), 10)
  var status = document.getElementById('sherlock-status')
  var form = document.getElementById('sherlock-form')
  var field = document.getElementById('sherlock-counter')
  if (!token || !digits || !form || !field) return

  // Compact SHA-256 over a string (UTF-8). A synchronous implementation is used
  // because it is several times faster here than awaiting crypto.subtle per hash.
  var K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2])
  var prefix = new TextEncoder().encode(token + ':')
  var w = new Uint32Array(64)

  function sha256(bytes) {
    var h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19])
    var len = bytes.length
    var padded = new Uint8Array(((len + 9 + 63) >> 6) << 6)
    padded.set(bytes)
    padded[len] = 0x80
    var bits = len * 8
    var dv = new DataView(padded.buffer)
    dv.setUint32(padded.length - 4, bits >>> 0)
    dv.setUint32(padded.length - 8, Math.floor(bits / 4294967296))
    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4)
      for (i = 16; i < 64; i++) {
        var a = w[i - 15], b = w[i - 2]
        var s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)
        var s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
      }
      var A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], H = h[7]
      for (i = 0; i < 64; i++) {
        var S1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))
        var ch = (E & F) ^ (~E & G)
        var t1 = (H + S1 + ch + K[i] + w[i]) | 0
        var S0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))
        var mj = (A & B) ^ (A & C) ^ (B & C)
        var t2 = (S0 + mj) | 0
        H = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0
      }
      h[0] = (h[0] + A) | 0; h[1] = (h[1] + B) | 0; h[2] = (h[2] + C) | 0; h[3] = (h[3] + D) | 0
      h[4] = (h[4] + E) | 0; h[5] = (h[5] + F) | 0; h[6] = (h[6] + G) | 0; h[7] = (h[7] + H) | 0
    }
    return h
  }

  function zeroDigits(h, n) {
    for (var i = 0; i < n; i++) {
      var word = h[i >> 3]
      if (((word >>> (28 - 4 * (i & 7))) & 0xf) !== 0) return false
    }
    return true
  }

  var counter = 0
  var started = Date.now()
  var announced = 0
  function step() {
    var deadline = Date.now() + 40
    while (Date.now() < deadline) {
      var digitsBytes = new TextEncoder().encode(String(counter))
      var msg = new Uint8Array(prefix.length + digitsBytes.length)
      msg.set(prefix)
      msg.set(digitsBytes, prefix.length)
      if (zeroDigits(sha256(msg), digits)) {
        field.value = String(counter)
        status.textContent = status.getAttribute('data-done')
        form.submit()
        return
      }
      counter++
    }
    var seconds = Math.floor((Date.now() - started) / 1000)
    if (seconds >= announced + 3) { // a screen reader hears progress without being flooded
      announced = seconds
      status.textContent = status.getAttribute('data-working') + ' (' + seconds + ' s)'
    }
    setTimeout(step, 0)
  }
  status.textContent = status.getAttribute('data-working')
  setTimeout(step, 0)
})()
