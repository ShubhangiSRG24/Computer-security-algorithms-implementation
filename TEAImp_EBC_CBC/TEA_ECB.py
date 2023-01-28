import os

from ctypes import c_uint32
path = os.path.join(os.getcwd(), 'msg.txt')

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

def open_file(filename, chunk_size):
        """
        Opens a file as binary and puts its content 
        into an array in which each array cell is 
        chunk_size bits in hexadecimal form written
        as string.
        """
        with open(filename, "rb") as f:
            hex_array = []
            for offset in range(0, os.path.getsize(filename), 8):
                hex_array.append(bytes.hex(f.read(8)))
                f.seek(offset + 8)

            f.close()
        
        return hex_array

      
if __name__ == '__main__':

  op_list= []
  result = ""
  actstr = ""
  op_list = open_file('msg.txt', 64)
  print(op_list)
  op_list.pop()
  print(op_list)

  K = 0xA56BABCD00000000FFFFFFFFABCDEF01
  u = [c_uint32(((MASK32 << x) & K) >> x).value for x in range(96,-1,-32)] 
  l0 = (int(hex(u[0]), 16))
  l1 = (int(hex(u[1]), 16))
  l2 = (int(hex(u[2]), 16))
  l3 = (int(hex(u[3]), 16))
  key = [l0, l1, l2, l3]

  for ih in op_list:
    P = int(ih, base=16)
    w = [c_uint32(((MASK32 << y) & P) >> y).value for y in range(64,-1,-32)]
    i0 = (int(hex(w[1]), 16))
    i1 = (int(hex(w[2]), 16))
    v=[i0,i1]
    value = [i0,i1]
    res = encrypt(value, key)
    result += (hex(res[0])[2:]+hex(res[1])[2:])
    res = decrypt(res, key)
    actstr += (hex(res[0])[2:]+hex(res[1])[2:])
  print(result)
  print(actstr)
  s = (bytes.fromhex(actstr).decode('utf-8'))
  print(s)


  f= open("msg.txt.enc","w+")
  f.write(result)
  f.close()

  f1= open("msg.txt.dec","w+")
  f1.write(s)
  f1.close()
