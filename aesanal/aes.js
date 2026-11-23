// AES-128-CBC algorithm
INV_SBOX = [
  [ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, ],
  [ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, ],
  [ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, ],
  [ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, ],
  [ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, ],
  [ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, ],
  [ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, ],
  [ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, ],
  [ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, ],
  [ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, ],
  [ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, ],
  [ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, ],
  [ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, ],
  [ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, ],
  [ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, ],
  [ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D, ],
];
SBOX = [
  [ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, ],
  [ 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, ],
  [ 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, ],
  [ 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, ],
  [ 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, ],
  [ 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, ],
  [ 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, ],
  [ 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, ],
  [ 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, ],
  [ 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, ],
  [ 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, ],
  [ 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, ],
  [ 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, ],
  [ 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, ],
  [ 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, ],
  [ 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, ],
];
RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
function subBytes4B(state) {
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      s = state[i][j];
      sl = s & 0x0f;
      sh = (s & 0xf0) >> 4;
      state[i][j] = SBOX[sh][sl];
    }
  }
  return state;
}
function invSubBytes4B(state) {
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      s = state[i][j];
      sl = s & 0x0f;
      sh = (s & 0xf0) >> 4;
      state[i][j] = INV_SBOX[sh][sl];
    }
  }
  return state;
}
function rowShift(state) {
  let temp = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = temp;
  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;
  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;

  temp = state[3][3];
  state[3][3] = state[2][3];
  state[2][3] = state[1][3];
  state[1][3] = state[0][3];
  state[0][3] = temp;
  return state;
}
function invRowShift(state) {
  let temp = state[0][3];
  state[0][3] = state[1][3];
  state[1][3] = state[2][3];
  state[2][3] = state[3][3];
  state[3][3] = temp;

  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;
  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;
  temp = state[3][1];
  state[3][1] = state[2][1];
  state[2][1] = state[1][1];
  state[1][1] = state[0][1];
  state[0][1] = temp;
  return state;
}

function xtime(x) {
  return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
}
function gfMul(a, b) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) result ^= a;
    a = xtime(a);
    b >>>= 1;
  }
  return result;
}
function modmul(n, b) {
  return gfMul(b, n);
}

//function modmul(n, b) {
//  let x = 0;
//  switch (n) {
//    case 2:
//      x = b << 1;
//      break;
//    case 3:
//      x = b ^ (b << 1);
//      break;
//    case 4: //09 = /1001
//      x = b ^ (b << 3);
//      break;
//    case 5: //0b = /1011
//      x = b ^ (b << 1) ^ (b << 3);
//      break;
//    case 6: //0d = /1101
//      x = b ^ (b << 2) ^ (b << 3);
//      break;
//    case 7: //0e = /1110
//      x = (b << 1) ^ (b << 2) ^ (b << 3);
//      break;
//  }
//  return x % 256;
//}
function mixColumn(state) {
  for (let i = 0; i < 4; i++) { // i is the column index
    let col = state[i];
    let new_col = [
      modmul(2, col[0]) ^ modmul(3, col[1]) ^ col[2] ^ col[3],
      col[0] ^ modmul(2, col[1]) ^ modmul(3, col[2]) ^ col[3],
      col[0] ^ col[1] ^ modmul(2, col[2]) ^ modmul(3, col[3]),
      modmul(3, col[0]) ^ col[1] ^ col[2] ^ modmul(2, col[3]),
    ];
    state[i] = new_col;
  }
  return state;
}
// 09 -> 4
// 0B -> 5
// 0D -> 6
// 0E -> 7
function invMixColumn(state) {
  for (let i = 0; i < 4; i++) { // i is the column index
    let col = state[i];
    let new_col = [
      modmul(7, col[0]) ^ modmul(5, col[1]) ^ modmul(6, col[2]) ^
      modmul(4, col[3]),
      modmul(4, col[0]) ^ modmul(7, col[1]) ^ modmul(5, col[2]) ^
      modmul(6, col[3]),
      modmul(6, col[0]) ^ modmul(4, col[1]) ^ modmul(7, col[2]) ^
      modmul(5, col[3]),
      modmul(5, col[0]) ^ modmul(6, col[1]) ^ modmul(4, col[2]) ^
      modmul(7, col[3]),
    ];
    state[i] = new_col;
  }
  return state;
}
function applyRoundKey(state, rKey) {
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      state[i][j] = state[i][j] ^ rKey[i][j];
    }
  }
  return state;
}
function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}
function subWord(word) {
  for (let i = 0; i < 4; i++) {
    s = word[i];
    sl = s & 0x0f;
    sh = (s & 0xf0) >> 4;
    word[i] = SBOX[sh][sl];
  }
  return word;
}
function xorWord(w1, w2) {
  return [w1[0] ^ w2[0], w1[1] ^ w2[1], w1[2] ^ w2[2], w1[3] ^ w2[3]];
}
function xorFull(u1, u2) {
  const u3 = new Uint8Array(u1.length);
  for (let i = 0; i < u1.length; i++) {
    u3[i] = u1[i] ^ u2[i];
  }
  return u3;
}
function schedKeys(key) {
  const fist = [
    [key[0], key[1], key[2], key[3]],
    [key[4], key[5], key[6], key[7]],
    [key[8], key[9], key[10], key[11]],
    [key[12], key[13], key[14], key[15]],
  ];
  const subkeys = [fist];
  for (let i = 1; i <= 10; i++) {
    const [w_4, w_3, w_2, w_1] = subkeys[i - 1];
    // first (i=4k case)
    const gg = subWord(rotWord(w_1));
    const w0 = xorWord(gg, [RC[i-1] ^ w_4[0], w_4[1], w_4[2], w_4[3]]);
    const w1 = xorWord(w0, w_3);
    const w2 = xorWord(w1, w_2);
    const w3 = xorWord(w2, w_1);
    subkeys.push([w0, w1, w2, w3]);
  }
  return subkeys;
}
function pack(l) {
  //return [
  //  [l[0], l[4], l[8], l[12]],
  //  [l[1], l[5], l[9], l[13]],
  //  [l[2], l[6], l[10], l[14]],
  //  [l[3], l[7], l[11], l[15]],,
  //];
  // for efficiency i pack the matrix as the transpose
  // then apply the operations in opposite manner
  // i.e.: rowShift actually shifts columsn and mixColumn
  // applies the matrix to each row.
  return [
    [l[0], l[1], l[2], l[3]],
    [l[4], l[5], l[6], l[7]],
    [l[8], l[9], l[10], l[11]],
    [l[12], l[13], l[14], l[15]],
  ];
}
function unpack(p) {
  return [
    p[0][0],
    p[0][1],
    p[0][2],
    p[0][3],
    p[1][0],
    p[1][1],
    p[1][2],
    p[1][3],
    p[2][0],
    p[2][1],
    p[2][2],
    p[2][3],
    p[3][0],
    p[3][1],
    p[3][2],
    p[3][3],
  ];
}
function core_encrypt(state_in, key) {
  const subkeys = schedKeys(key);
  //console.log(subkeys);
  let state = JSON.parse(JSON.stringify(state_in));
  state = applyRoundKey(state, subkeys[0]);
  console.debug(state);
  for (let round = 1; round <= 9; round++) {
    state = subBytes4B(state);
    state = rowShift(state);
    state = mixColumn(state);
    state = applyRoundKey(state, subkeys[round]);
  }
  // round 10 has no mix columns
  state = subBytes4B(state);
  state = rowShift(state);
  state = applyRoundKey(state, subkeys[10]);
  return state;
}
function core_decrypt(state_in, key) {
  const subkeys = schedKeys(key);
  //console.log(subkeys);
  let state = JSON.parse(JSON.stringify(state_in));
  state = applyRoundKey(state, subkeys[10]);
  for (let round = 9; round >= 1; round--) {
    state = invRowShift(state);
    state = invSubBytes4B(state);
    state = applyRoundKey(state, subkeys[round]);
    state = invMixColumn(state);
  }
  // round 10 has no mix columns
  state = invRowShift(state);
  state = invSubBytes4B(state);
  console.debug(state);
  state = applyRoundKey(state, subkeys[0]);
  return state;
}
function cbc_encrypt(u8arr, iv, key) {
  const output = new Uint8Array(u8arr.length);
  let c = iv;
  let p = null;
  for (let block = 0; block < u8arr.length / 16; block++) {
    p = u8arr.slice(block * 16, (block + 1) * 16);
    p = xorFull(p, c);
    c = unpack(core_encrypt(pack(p), key));
    for (let i = 0; i < 16; i++) {
      output[block * 16 + i] = c[i];
    }
  }
  return output;
}
function cbc_decrypt(u8arr, iv, key) {
  const output = new Uint8Array(u8arr.length);
  let p = iv;
  let c = null;
  let cp = iv;
  for (let block = 0; block < u8arr.length / 16; block++) {
    c = u8arr.slice(block * 16, (block + 1) * 16);
    cp = c.slice();
    c = unpack(core_decrypt(pack(c), key));
    p = xorFull(p, c);
    for (let i = 0; i < 16; i++) {
      output[block * 16 + i] = p[i];
    }
    p = cp;
  }
  return output;
}
function cookStringMessage(str) {
  const h = new TextEncoder().encode(str);
  let len = h.length;
  let pad = 0;
  while (len % 16 != 0) {
    len++;
    pad++;
  } // padding
  let u = new Uint8Array(len);
  for (let i = 0; i < h.length; i++) {
    u[i] = h[i];
  }
  return [u, pad];
}
function eatStringMessage(u, pad) {
  u = u.slice(0, u.length - pad);
  return new TextDecoder().decode(u);
}
function createKeyFromPass(pass) {
  pass = pass.substring(0, 16);
  let str = pass;
  let i = 0;
  while (str.length != 16) {
    str += pass[i++];
    i %= pass.length;
  }
  const [u, _] = cookStringMessage(str);
  const e = unpack(core_encrypt(pack(u), sample_key));
  return Array.from(e);
}
//const sample_key = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20];
const sample_key = [
  0x74,
  0x17,
  0xef,
  0x5d,
  0x9c,
  0x54,
  0xcd,
  0xfa,
  0x18,
  0x7,
  0xe1,
  0x57,
  0xc0,
  0x16,
  0xd2,
  0x19,
];

