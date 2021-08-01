# script that I used to look up values and dump constants out of memory dumps produced by Ghidra emulator. Very rough.
import struct
import gzip
import sys
import os
fl1=sys.argv[1]
#fl2=sys.argv[2]
srch=None
if len(sys.argv)>2:
  srch=sys.argv[2]
def readRegister(dct,fl):
  dt=fl.read(2)
  if len(dt)<2: return False
  nmlen=struct.unpack("<H",dt)[0]
  nml=fl.read(nmlen)
  if len(nml)<nmlen: return False
  nm=nml.decode("ascii")
  dt=fl.read(2)
  if len(dt)<2: return False
  ln=struct.unpack("<H",dt)[0]
  if ln==16:
    dt=fl.read(16)
    if len(dt)<16: return False
    vals=struct.unpack("<QQ",dt)
    val=(vals[0]<<64)+vals[1]
  elif ln==8:
    dt=fl.read(8)
    if len(dt)<8: return False
    val=struct.unpack("<Q",dt)[0]
  elif ln==4:
    dt=fl.read(4)
    if len(dt)<4: return False
    val=struct.unpack("<I",dt)[0]
  else:
    dt=fl.read(2)
    if len(dt)<2: return False
    val=struct.unpack("<H",dt)[0]
  if not "registers" in dct:
    dct["registers"]={}
  dct["registers"][nm]=val
  return True
def readMemoryChunk(dct,fl):
  if not "mem" in dct:
    dct["mem"]={}
  dt=fl.read(8)
  if len(dt)<8: return False
  start=struct.unpack("<Q",dt)[0]
  dt=fl.read(8)
  if len(dt)<8: return False
  ln=struct.unpack("<Q",dt)[0]
  if ln>0:
    dat=fl.read(ln)
    if len(dat)<ln: return False
    dct["mem"][start]=dat
  return True
def readSnapshot(dct,fl):
  numreg=struct.unpack("<I",fl.read(4))[0]
  for i in range(numreg):
    if not readRegister(dct,fl):
      print("Corrupt snapshot: not enough registers")
      return
  while readMemoryChunk(dct,fl):
    pass

basedir="./"
def loadSnapshot(dct,name):
  global basedir
  fname=os.path.join(basedir,name)
  with gzip.open(fname, 'rb') as f:
    readSnapshot(dct,f)
kt={}
loadSnapshot(kt,fl1)
print(kt["mem"].keys())
import codecs
st="22e54cd8"#"22E54CD8A10671840752EF46"
if srch is not None:
  st=srch
bts=codecs.decode(st,"hex")
def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub)

for offs in kt["mem"]:
  i=list(find_all(kt["mem"][offs],bts))
  for ko in i:
    print("{:x}".format(offs+ko))
def readAddr(dct,addr,nm):
  for offs in kt["mem"]:
    if offs<=addr and offs+len(kt["mem"][offs])>=addr:
      dt=kt["mem"][offs]
      return dt[addr-offs:addr-offs+nm]
def readULL(dct,addr):
  dt=readAddr(dct,addr,8)
  return struct.unpack("<Q",dt)[0]
def readUI(dct,addr):
  dt=readAddr(dct,addr,4)
  return struct.unpack("<I",dt)[0]
def readUS(dct,addr):
  dt=readAddr(dct,addr,2)
  return struct.unpack("<H",dt)[0]
def readByte(dct,addr):
  dt=readAddr(dct,addr,1)
  return struct.unpack("<c",dt)[0][0]

def lesserConstShuffle(const,p1,p2):
  global kt
  ret=[]
  length=(const  >> 0x24) & 0x3fff
  offset=(const  & 0x3fffff)
  if length>0:
   eax=0
   ret=[0]*length
   for k in range(length):
     eax=eax&0xf8
     #print("{:b}".format(eax))
     fl=p1[k]
     eax=eax^fl
     f2=(p2[k]<<8)
     fl=f2+eax
     f3=readByte(kt,offset+k+0x180a85ad0)<<11
     #print(readByte(kt,offset+k+0x180a25040))
     fl=fl+f3
     eax=readByte(kt,0x1809cde30+fl)
     ret[k]=eax&7
  return ret
def cnstShuffle(const,p1,p2):
  global kt
  ret=[]
  length=(const  >> 0x24) & 0x3fff
  offset=(const  & 0x3fffff)
  slen=(const >>0x32)
  if length>0:
   eax=0
   ret=[0]*length
   for k in range(length):
     eax=eax&0xf8
     #print("{:b}".format(eax))
     fl=p1[k]
     eax=eax^fl
     f2=(p2[k]<<8)
     fl=f2+eax
     f3=readByte(kt,offset+k+0x180a25040)<<11
     #print(readByte(kt,offset+k+0x180a25040))
     fl=fl+f3
     eax=readByte(kt,0x1809cde30+fl)
     ret[k]=eax&7
  if slen>0:
    while len(ret)<slen+length:
      ret.append(0)
    for l in range(slen):
      k=l+length
      eax=eax&0xf8
      esi=(p2[k]<<8)
      esi=esi|eax
      eax=(readByte(kt,offset+k+0x180a25040)<<11)
      eax=(eax^esi)
      eax=readByte(kt,0x1809cde30+eax)
      ret[k]=eax&7
  return ret
def otherShuffle(const,p1,p2):
  global kt
  ret=[]
  length=(const  >> 0x24) & 0x3fff
  offset=(const  & 0x3fffff)
  sublen=(const >> 0x16) & 0x3fff
  if sublen ==0:
    eax=0
  else:
    eax=0
    rtval=0
    for a in range(sublen):
      eax=(readByte(kt,offset+a+0x180a25040)<<11)+(p2[a]<<8)+(eax&0xf8)+(p1[a]&0x7)
      eax=readByte(kt,0x1809cde30+fl)
  slen=(const >>0x32)
  if length>0:
   eax=0
   ret=[0]*length
   for k in range(length):
     eax=eax&0xf8
     fl=p1[k+sublen]
     eax=eax^fl
     f2=(p2[k+sublen]<<8)
     fl=f2+eax
     f3=readByte(kt,offset+k+sublen+0x180a25040)<<11
     #print(readByte(kt,offset+k+0x180a25040))
     fl=fl+f3
     eax=readByte(kt,0x1809cde30+fl)
     ret[k]=eax&7
  if slen>0:
    while len(ret)<slen+length+sublen:
      ret.append(0)
    for l in range(slen):
      k=l+length+sublen
      eax=eax&0xf8
      esi=(p2[k]<<8)
      esi=esi|eax
      eax=(readByte(kt,offset+k+0x180a25040)<<11)
      eax=(eax^esi)
      eax=readByte(kt,0x1809cde30+eax)
      ret[k]=eax&7
  return ret

def cnPack(lst,stp=0):
  eax=0
  ret=[]
  for k in range(stp,len(lst),1):
    ebx=lst[k]&3
    ebx=(ebx<<(eax&6))# 110
    ecx=((k-stp)>>2)
    while len(ret)<ecx+1: ret.append(0)
    ret[ecx]|=ebx
    eax+=2
  return ret
def cnUnpack(lst,ln=None):
  ret=[]
  for k in range(len(lst)):
    l=lst[k]
    ret.append(l&0x3)
    ret.append((l>>2)&0x3)
    ret.append((l>>4)&0x3)
    ret.append((l>>6)&0x3)
  if ln is not None:
   while(len(ret)<ln): ret=[0,*ret]
  return ret

"""
Tables:
each side has 3 bits (permuted) - 8 values. 4 have carry
Many tables do who-knows-what XD
some are "sum" tables  -can be recognized by the fact that they have all values in each row if varied (and can be permuted to symmetrical form)
With additional "carry" sum tables can affect up to 3 cells forward by variation (more if other cells are full) 
Some are normalizer, work on the doubled arguments (a=b) and allow to pack data afterwards... 
a+carry(b) table? (carry  goes to next "digit" - interleaved??
table has separate encodings for a,b,c (8x8 table)
etc ...
"""

#0x12000027448  -sum table, it seems
#0x1200002b000  - another sum table?
#0x12000026a1b - normalizer table...
#0x25000037501 - carry flipper?
#0x1000002cd3a  - carry ... no-flipper? not sure
for q in range(8):
 ls=[]
 for w in range(8):
  a2=[1]*0x40e
  a1=[1]*0x40e
  a1[0]=0
  a2[0]=0
  a1[1]=q
  a2[1]=1
  a1[2]=w
  a2[2]=w
  #a3=cnstShuffle(0x12000033f37,a1,a2) #0x120000054d6
  a3=cnstShuffle(0x12000033f37,a1,a1) #0x120000054d6
  #print(a3)
  ls.append(a3[4])
 print("{}:  {}".format(q,ls))
carry=0

def printTC(num):
 offs=num<<11
 ecr=set()
 print("TC {}".format(num))
 for carry in range(32):
  st=[]
  for q in range(8):
   dm=offs+(q<<8)+(carry<<3)+q
   dt=readByte(kt,0x1809cde30+dm)
   ec=dt>>3
   vl=dt&7
   st.append(vl)
   ecr.add(ec)
  print("{}: {}".format(carry,st))
 print(ecr)
printTC(22)
printTC(47)
sys.exit()
for ss in range(256):
    offs=ss<<11
    crr=set()
    print("Table # {}".format(ss))
    for q in range(8):
     ls=[]
     for w in range(8):
       dm=offs+(q<<8)+(carry<<3)+w
       dt=readByte(kt,0x1809cde30+dm)
       ls.append([dt>>3,dt&0x7])
       crr.add(dt>>3)
     print("{}:  {}".format(q,ls))  
    print("Carries: {} {}".format(len(crr),crr))
print("{:x}".format(readULL(kt,0x181253ac8)))
llen=38848

with open("dats.lg","r") as fl:
  for ln in fl:
    ls=ln.strip()
    if "DAT" in ls:
      offs=ls.split("_")[1]
      l=[]
      for i in range(llen):
       l.append(readByte(kt,int("0x"+offs,16)+i))
      ssl='{'+', '.join(["{}".format(k) for k in l])+'};';
      print("unsigned char DAT_{} [{}]={}".format(offs,len(l),ssl))
    elif "INT" in ls:
      offs=ls.split("_")[1]
      l=[]
      for i in range(llen):
       l.append(readUI(kt,int("0x"+offs,16)+i*4))
      ssl='{'+', '.join(["{}".format(k) for k in l])+'};';
      print("unsigned int INT_{} [{}]={}".format(offs,len(l),ssl))
    elif "QWORD" in ls:
      offs=ls.split("_")[1]
      l=[]
      for i in range(llen):
       l.append(readULL(kt,int("0x"+offs,16)+i*8))
      ssl='{'+', '.join(["{}".format(k) for k in l])+'};';
      print("unsigned long long QWORD_{} [{}]={}".format(offs,len(l),ssl))
