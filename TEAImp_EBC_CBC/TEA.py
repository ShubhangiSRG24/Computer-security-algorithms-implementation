from ctypes import c_uint32

MASK32 = 0xffffffff 

def encrypt(v, k):
  v0, v1 = c_uint32(v[0]), c_uint32(v[1])
  delta = 0x9e3779b9
  k0, k1, k2, k3 = k[0], k[1], k[2], k[3]
  total = c_uint32(0)
  for i in range(32):
    total.value += delta
    v0.value += ((v1.value<<4) + k0) ^ (v1.value + total.value) ^ ((v1.value>>5) + k1)
    v1.value += ((v0.value<<4) + k2) ^ (v0.value + total.value) ^ ((v0.value>>5) + k3)
  return v0.value, v1.value
def decrypt(v, k):
  v0, v1 = c_uint32(v[0]), c_uint32(v[1])
  delta = 0x9e3779b9
  k0, k1, k2, k3 = k[0], k[1], k[2], k[3]
  total = c_uint32(delta<<5)
  for i in range(32):
    v1.value -= ((v0.value<<4) + k2) ^ (v0.value + total.value) ^ ((v0.value>>5) + k3)
    v0.value -= ((v1.value<<4) + k0) ^ (v1.value + total.value) ^ ((v1.value>>5) + k1)
    total.value -= delta
  return v0.value, v1.value


"""
Output answers
"""

if __name__ == '__main__':
    

    # TEA ALGORITHM
    K = 0xA56BABCD00000000FFFFFFFFABCDEF01
    P = 0x0123456789ABCDEF

    w = [c_uint32(((MASK32 << y) & P) >> y).value for y in range(64,-1,-32)]
    i0 = (int(hex(w[1]), 16))
    i1 = (int(hex(w[2]), 16))

    v=[i0,i1]

    value = [i0,i1]
    u = [c_uint32(((MASK32 << x) & K) >> x).value for x in range(96,-1,-32)] 
    l0 = (int(hex(u[0]), 16))
    l1 = (int(hex(u[1]), 16))
    l2 = (int(hex(u[2]), 16))
    l3 = (int(hex(u[3]), 16))
    key = [l0, l1, l2, l3]
    print("Data is : ", (hex(P)[2:]).zfill(16))
    res = encrypt(value, key)
    e = (hex(res[0])[2:]).zfill(8)+(hex(res[1])[2:]).zfill(8)
    print("Encrypted data is : ", e)
    res = decrypt(res, key)
    c = (hex(res[0])[2:]).zfill(8)+(hex(res[1])[2:]).zfill(8)
    print("Decrypted data is : ", c)
    print("DEC data:", c)