#simple script that shows how to unmask OAEP padding from big integer
import hashlib

def i2osp(integer, size):
    return bytes([((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])

def mgf1(input_str, length, hash=hashlib.sha1):
    """Mask generation function."""
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash(input_str + C).digest()
        counter += 1
    return output[:length]
def decode(bts,seed):
  zr=mgf1(bts,20)
  sd=bytearray()
  for (a,b) in zip(seed,zr):
   sd.append(a^b)
  seed=bytes(sd)
  xormask=mgf1(seed,len(bts))
  ret=bytearray()
  for (a,b) in zip(bts,xormask):
   ret.append(a^b)
  return bytes(ret)
ii=int("e4ae6c475d00d73552eae63d3456cd59f17e0f4bbad2a587d34c774658b9b5ce7857491e6e06fbc79cc8f688ad20e9c2f6d65419b3ec86657c1b87a80cd4a5c012a1d7571b842ff7c0f56c1d83ae003b73e73633f65f4c3644f0570c57dffa72f7e00788365a0726511b05bb3d440777770742cc776f3266456755b803b3743a0cd1b139d2a8522b1f6e4970afd74096a9e11abbdbfdb06b10a529877840e825d42b117c285bb064fc4778dd4242cb2e9df49e63c3ab60dc54a0f2d45126683bb71602bf5963468e56e8e84bc6c58c3c68f4670b080937db93aa22d90f35d8e8767654965f40b2fde20a84d2d57e9e12ecf9dddf02c3943cb0d2f513d0c965",16).to_bytes(256,'big')
print("isValidPrefix={}".format(ii[0]==0))
print("Masked data: {}".format(ii[21:].hex()))
print("Seed Mask: {}".format(mgf1(ii[21:],20).hex()))
print("Unmasked data: {}".format(decode(ii[21:],ii[1:21]).hex()))
