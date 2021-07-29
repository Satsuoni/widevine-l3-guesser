# Simple attempt emulate suspicious functions in widewine (4.10.2209.0). Adjust to taste (starting point, logs, etc) and run while project is open.  
#@author Satsuoni
#@category Deobfuscation
#@keybinding 
#@menupath 
#@toolbar 

from binascii import hexlify
import logging
from ghidra.app.emulator import EmulatorHelper
#from ghidra.program.model.symbol import SymbolUtilities
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import *
from ghidra.program.model.pcode import JumpTable
from java.util import LinkedList, Arrays, ArrayList
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import Register
from ghidra.program.model.lang import OperandType
from ghidra.program.model.lang import RegisterManager
import array
import sys
logger = logging.getLogger("")
logger.setLevel(logging.DEBUG)
handler1=logging.StreamHandler(sys.stdout)
class WarnFormatter(logging.Formatter):
    err_fmt  = "ERROR: %(msg)s"
    warn_fmt  = "Warning: %(msg)s"
    dbg_fmt  = "DBG: %(module)s: %(lineno)d: %(msg)s"
    info_fmt = "%(msg)s"
    def __init__(self, fmt="%(levelno)s: %(msg)s"):
        logging.Formatter.__init__(self, fmt)

    def format(self, record):
        # Save the original format configured by the user
        # when the logger formatter was instantiated
        format_orig = self._fmt
        # Replace the original format with one customized by logging level
        if record.levelno == logging.DEBUG:
            self._fmt = WarnFormatter.dbg_fmt
        elif record.levelno == logging.INFO:
            self._fmt = WarnFormatter.info_fmt
        elif record.levelno == logging.ERROR:
            self._fmt = WarnFormatter.err_fmt
        elif record.levelno == logging.WARNING:
           self._fmt = WarnFormatter.warn_fmt
        # Call the original formatter class to do the grunt work
        result = logging.Formatter.format(self, record)
        # Restore the original format configured by the user
        self._fmt = format_orig
        return result
        
formatter = WarnFormatter('%(message)s')
handler1.setFormatter(formatter)
handler2=logging.FileHandler("trunlog.log", mode='w', encoding="utf-8")
handler2.setFormatter(formatter)
logger.addHandler(handler1)
logger.addHandler(handler2)

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    
def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers
def step(emu,monitor):
 success = emu.step(monitor)
 if (success == False):
   lastError = emu.getLastError()
   logger.error("Emulation Error: '{}'".format(lastError))
 return success
def isCallInstruction(instr):
    if instr is None:
        return False
    flowType = instr.getFlowType()
    if flowType.isCall():
      return True
    return False

# 009bc60e heap alloc. No free available or necessary
class FakeMemory(object):
  def __init__(self,startpoint):
    self.start=startpoint
    self.curpoint=self.start
  def allocate(self,ln):
    rpoint=self.curpoint
    self.curpoint+=ln
    return rpoint
mem=FakeMemory( 0x000000F02FFF0000)

def EmuRet(emu,offs=0):
  pos=emu.readStackValue(0,8,False)
  emu.writeRegister(emu.getPCRegister(), pos)
  stack=emu.readRegister("RSP")
  emu.writeRegister("RSP",stack+8+offs)
  
def OperatorNew(emu):
  bytes=emu.readRegister("RCX")
  ptr=mem.allocate(bytes)
  logger.info("Allocating (new) {} bytes to {:x}".format(bytes,ptr))
  emu.writeRegister("RAX",ptr)
  EmuRet(emu)
  
def HeapAlloc(emu):
  bytes=emu.readRegister("R8")
  logger.info("Allocating {} bytes".format(bytes))
  ptr=mem.allocate(bytes)
  emu.writeRegister("RAX",ptr)
  EmuRet(emu)
def MFree(emu):
  bt2=emu.readRegister("R8")
  logger.info("Freed something at {:x}".format(bt2))
  emu.writeRegister("RAX",bt2)
  EmuRet(emu)
  
def EnterCriticalSection(emu):
  EmuRet(emu)
  
def TryAcquireSRWLockExclusive(emu):
  emu.writeRegister("RAX",1)
  EmuRet(emu)
  
tlsval=1
tlsstorage={}
def TlsAlloc(emu):
  global tlsval
  emu.writeRegister("RAX",tlsval)
  tlsval+=1
  EmuRet(emu)
def TlsSetValue(emu):
 global tlsval,tlsstorage
 index=emu.readRegister("RCX")
 value=emu.readRegister("RDX")
 tlsstorage[index]=value
 emu.writeRegister("RAX",1)
 EmuRet(emu)
 
def TlsGetValue(emu):
 global tlsval,tlsstorage
 index=emu.readRegister("RCX")
 if index in tlsstorage:
   emu.writeRegister("RAX",tlsstorage[index])
 else:
   emu.writeRegister("RAX",0)
 EmuRet(emu)
def QueryPerformanceFrequency(emu):
 offs=emu.readRegister("RCX")
 emu.writeMemoryValue(getAddress(offs),8,1000)
 emu.writeRegister("RAX",1)
 EmuRet(emu)

def Ret0(emu):
  emu.writeRegister("RAX",0)
  EmuRet(emu)
def Ret1(emu):
  emu.writeRegister("RAX",1)
  EmuRet(emu)
def Ret1st(emu):
  emu.writeRegister("RAX",emu.readRegister("RCX"))
  EmuRet(emu)
time_cnt=0
def timeGetTime(emu):
  global time_cnt
  emu.writeRegister("RAX",time_cnt)
  time_cnt+=1
  EmuRet(emu)

last_error=-20
def LoadLibrary(emu):
  global last_error
  offs=emu.readRegister("RCX")
  lname=emu.readMemory(getAddress(offs),200)
  logger.info("Load library: {}".format(lname))
  emu.writeRegister("RAX",0)
  last_error=-21
  EmuRet(emu)
def GetLastError(emu):
  global last_error
  emu.writeRegister("RAX",last_error)
  EmuRet(emu)
def SetLastError(emu):
  global last_error
  last_error=emu.readRegister("RCX")
  EmuRet(emu)

def getptd_noexit(emu):
  global mem
  tiddata=mem.allocate(256) # _tiddata
  emu.writeRegister("RAX",tiddata)
  EmuRet(emu)

def findwindowA(emu):
  lpclass=emu.readRegister("RCX")
  lpname=emu.readRegister("RDX")
  logger.info(emu.readNullTerminatedString(getAddress(lpclass),200))
  logger.info(emu.readNullTerminatedString(getAddress(lpname),200))
  emu.writeRegister("RAX",0)
  EmuRet(emu)
def InitThreadHeader(emu):
  mm=emu.readRegister("RCX")
  logger.info("Init Thread header?")
  emu.writeMemoryValue(getAddress(mm),4,-1)
  EmuRet(emu)
def InitThreadFooter(emu):
  mm=emu.readRegister("RCX")
  logger.info("Init Thread footer?")
  emu.writeMemoryValue(getAddress(mm),4,-1)
  EmuRet(emu)
def GetRandom(emu):
  ptr=emu.readRegister("RCX")
  len=emu.readRegister("RDX")
  logger.info("Random... kinda")
  for a in range(len):
    emu.writeMemoryValue(getAddress(ptr),1,0xaf)
    ptr+=1
  emu.writeRegister("RAX",1)
  EmuRet(emu)
  
dict={}
dict[getAddress(0x009bc60e )]=HeapAlloc
dict[getAddress(0x009bc1ec )]=EnterCriticalSection
dict[getAddress(0x009bc61a )]=MFree
dict[getAddress(0x009bcae2 )]=TlsAlloc
dict[getAddress(0x009bcb06 )]=TlsSetValue
dict[getAddress(0x009bcaf8 )]=TlsGetValue
dict[getAddress(0x009bcb14 )]=TryAcquireSRWLockExclusive
dict[getAddress(0x009bc8d6 )]=EnterCriticalSection #void 
dict[getAddress(0x009bc874 )]=QueryPerformanceFrequency
dict[getAddress(0x009bccb6 )]=timeGetTime
dict[getAddress(0x009bc7f6 )]=LoadLibrary
dict[getAddress(0x009bc422 )]=GetLastError
dict[getAddress(0x18052d44c)]=EnterCriticalSection #FlsSetValue
dict[getAddress(0x009bc7ba )]=EnterCriticalSection #LeaveCriticalSection
dict[getAddress(0x009bcce8 )]=findwindowA
dict[getAddress(0x009bc4ae )]=Ret0 #GetModuleHandle
dict[getAddress(0x009bc4e4 )]=Ret0 #GetProcAddress
dict[getAddress(0x009bcc80 )]=GetRandom #SystemFunction036
dict[getAddress(0x009bc81c )]=EnterCriticalSection #OutputDebugString - void
dict[getAddress(0x009bc392 )]=Ret1 #GetCurrentThreadId
dict[getAddress(0x009bc100 )]=Ret0 #AcquireSRWLockExclusive

dict[getAddress(0x18052cc50)]=getptd_noexit
dict[getAddress(0x009bca2a )]=SetLastError
 
dict[getAddress(0x180256270)]=Ret0 #GetCurrentDir??

dict[getAddress(0x18050f1c0)]=OperatorNew

#dict[getAddress(0x180111f45)]=Ret1 #probably a table generator.  Very slow, but nothing works after without it

dict[getAddress(0x18050f330)]=InitThreadHeader
dict[getAddress(0x18050f3c8)]=InitThreadFooter
dict[getAddress(0x180256d10)]=Ret1st
dict[getAddress(0x18050f580)]=EnterCriticalSection

def allocLargeStdstring(emu,len):
  ptr=mem.allocate(24)
  emu.writeMemoryValue(getAddress(ptr+8),8,len)
  emu.writeMemoryValue(getAddress(ptr+16),8,len)
  buf=mem.allocate(len)
  emu.writeMemoryValue(getAddress(ptr),8,buf)
  return ptr



def HostAllocate(emu):
  bytes=emu.readRegister("RDX")
  logger.info("HostAllocate: {} bytes".format(bytes))
  ptr=mem.allocate(bytes)
  emu.writeRegister("RAX",ptr)
  EmuRet(emu)
dict[getAddress(0x0aa01)]=HostAllocate

def HostSetTimer(emu):
  delay=emu.readRegister("RDX")
  logger.info("HostSetTimer: {} msec".format(delay))
  EmuRet(emu)
dict[getAddress(0x0aa02)]=HostSetTimer

def HostGetCurrentWallTime(emu):
   logger.info("HostGetCurrentWallTime")
   emu.writeRegister("XMM0",0)
   EmuRet(emu)
dict[getAddress(0x0aa03)]=HostGetCurrentWallTime

def HostOnInitialized(emu):
   success=emu.readRegister("EDX")
   logger.info("OnInitialized : maybe?: {}".format(success))
   EmuRet(emu)
dict[getAddress(0x0aa04)]=HostOnInitialized


def HostOnResolveKeyStatusPromise(emu):
  prid=emu.readRegister("EDX")
  logger.info("HostOnResolveKeyStatusPromise : {}".format(prid))
  EmuRet(emu)
dict[getAddress(0x0aa05)]=HostOnResolveKeyStatusPromise
  
  
def HostOnResolveNewSessionPromise(emu):
  prid=emu.readRegister("EDX")
  sesid=emu.readRegister("R8")
  logger.info("OnResolveNewSessionPromise : {} {}".format(prid,sesid))
  EmuRet(emu)

dict[getAddress(0x0aa06)]=HostOnResolveNewSessionPromise

def HostOnResolvePromise(emu):
  prid=emu.readRegister("EDX")
  logger.info("HostOnResolvePromise : {}".format(prid))
  EmuRet(emu)
  
dict[getAddress(0x0aa07)]=HostOnResolvePromise
  
  
def HostOnRejectPromise(emu):
  prid=emu.readRegister("EDX")
  ex=emu.readRegister("R8")
  sc=emu.readRegister("R9")
  logger.info("HostOnRejectPromise : {} Exc: {} sc: {}".format(prid,ex,sc ))
  EmuRet(emu,8)

dict[getAddress(0x0aa08)]=HostOnRejectPromise

def HostOnSessionMessage(emu):
   saveSnapshot(emu,"OnSessionMessage.gz")
   messSize=emu.readStackValue(0x30,8,False)
   print(messSize)
   messPtr=emu.readStackValue(0x28,8,False)
   mtype=emu.readRegister("R9")
   logger.info("message_type")
   logger.info(mtype)
   mm=emu.readMemory(getAddress(messPtr),int(messSize))
   logger.info("OnSessionMessage {} {}  ".format( mtype, mm))
   rmsg=""
   for a in mm:
     if a<0: a=256+a
     rmsg+="{:02X}".format(a)
   logger.info(rmsg)
   raise 999
   EmuRet(emu,8)

dict[getAddress(0x0aa09)]=HostOnSessionMessage

def HostOnSessionKeysChange(emu):
   logger.info("HostOnSessionKeysChange")
   EmuRet(emu,8)

dict[getAddress(0x0aa0a)]=HostOnSessionKeysChange

def HostOnExpirationChange(emu):
   logger.info("HostOnExpirationChange")
   EmuRet(emu)

dict[getAddress(0x0aa0b)]=HostOnExpirationChange

def HostOnSessionClosed(emu):
   logger.info("HostOnSessionClosed")
   EmuRet(emu)
dict[getAddress(0x0aa0c)]=HostOnExpirationChange

def HostSendPlatformChallenge(emu):
   logger.info("HostSendPlatformChallenge")
   EmuRet(emu)

dict[getAddress(0x0aa0d)]=HostSendPlatformChallenge

def HostEnableOutputProtection(emu):
   logger.info("HostEnableOutputProtection")
   EmuRet(emu)
dict[getAddress(0x0aa0e)]=HostEnableOutputProtection

def HostQueryOutputProtectionStatus(emu):
   logger.info("HostQueryOutputProtectionStatus")
   EmuRet(emu)
dict[getAddress(0x0aa0f)]=HostQueryOutputProtectionStatus
def HostOnDeferredInitializationDone(emu):
   logger.info("HostOnDeferredInitializationDone")
   EmuRet(emu)
dict[getAddress(0x0aa10)]=HostOnDeferredInitializationDone

def HostCreateFileIO(emu):
   logger.info("HostCreateFileIO")
   emu.writeRegister("RAX",0)
   EmuRet(emu)
dict[getAddress(0x0aa11)]=HostCreateFileIO

def HostRequestStorageId(emu):
   logger.info("HostRequestStorageId")
   EmuRet(emu)
dict[getAddress(0x0aa12)]=HostRequestStorageId


# create Host structure+vtable
def allocHost(emu):
  vt_ptr=mem.allocate(8*16)
  ptr=vt_ptr
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa01)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa02)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa03)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa04)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa05)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa06)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa07)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa08)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa09)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0a)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0b)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0c)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0d)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0e)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa0f)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa10)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa11)
  ptr+=8
  emu.writeMemoryValue(getAddress(ptr),8,0x0aa12)
  cls=mem.allocate(8)
  emu.writeMemoryValue(getAddress(cls),8,vt_ptr)
  return cls
def makeHost(emu):
  logger.info("Getting host")
  ptr=allocHost(emu)
  emu.writeRegister("RAX",ptr)
  EmuRet(emu)
  
def isCallOther(instr):
  if instr is None:
    return False
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.CALLOTHER:
      return True
  return False
def getCallOtherName(instr):
  if instr is None:
    return None
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.CALLOTHER:
      return currentProgram.getLanguage().getUserDefinedOpName(code.getInput(0).getOffset())
  return None
  

def skip(emu):
  executionAddress = emu.getExecutionAddress() 
  instr=getInstructionAt(executionAddress)
  nextInstr=instr.getNext()
  lval = int("0x{}".format(nextInstr.getAddress()), 16)
  emu.writeRegister(emu.getPCRegister(), lval)
  
dict[getAddress(0xf0000)]=makeHost
initCdm=getAddress(0x180001040)

monitor=ConsoleTaskMonitor()
rspStart=0x000000002FFF0000
emu=EmulatorHelper(currentProgram)
startaddr=initCdm#getAddress(0x18017e3b0)
cur_fun=getFunctionContaining(startaddr)
mainFunctionEntryLong = int("0x{}".format(cur_fun.getEntryPoint()), 16)
emu.writeRegister(emu.getPCRegister(), mainFunctionEntryLong)
emu.writeRegister("RSP", rspStart)
emu.writeRegister("RBP", 0x000000002FFF0000)
datstring=allocLargeStdstring(emu,256)
emu.writeRegister("RDX",datstring)

#clearkeys = "org.w3.clearkey"
import struct
def readULL(emu,addr):
  dat=emu.readMemory(addr,8)
  cdv=struct.unpack("<Q",dat)[0]
  return cdv
def get_cptr(emu,string):
  ptr=mem.allocate(len(string)+1)
  emu.writeMemory(getAddress(ptr),string.encode("utf-8"))
  emu.writeMemory(getAddress(ptr+len(string)),b'\0')
  return ptr

def listToMem(emu,lst):
  ptr=mem.allocate(len(lst)+1)
  emu.writeMemory(getAddress(ptr),array.array('B',lst).tostring())
  emu.writeMemory(getAddress(ptr+len(lst)),b'\0')
  logger.info("Written memory is: {}".format(emu.readMemory(getAddress(ptr),len(lst))))
  logger.info("Lst is is: {}".format(array.array('B',lst)))
  return ptr
def EmuPush(emu,val):
  stack=emu.readRegister("RSP")
  stack=stack-8
  emu.writeRegister("RSP",stack)
  emu.writeMemoryValue(getAddress(stack), 8,val)
def EmuPull(emu,offs):
  stack=emu.readRegister("RSP")
  stack=stack+offs
  emu.writeRegister("RSP",stack)
# +x30 +x20
def EmuPush4(emu,val):
  stack=emu.readRegister("RSP")
  stack=stack-4
  emu.writeRegister("RSP",stack)
  emu.writeMemoryValue(getAddress(stack), 4,val)
def isReturn(instr):
  if instr is None:
    return False
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.RETURN:
      return True
  return False
  
#fill process information blocks with varying garbage
emu.writeRegister("GS_OFFSET",0x3f000)
threadinfo=mem.allocate(1024)
pptr=threadinfo
#fill with the same struct 128 times
threaddata=mem.allocate(1024)

for a in range(128): 
  emu.writeMemoryValue(getAddress(pptr),8,threaddata)
  pptr+=8

for a in range(1024): 
  emu.writeMemoryValue(getAddress(threaddata+a),1,0xff)

  
emu.writeMemoryValue(getAddress(0x3f058),8,threadinfo)

logger.info("GS:  {:x}".format(emu.readRegister("GS_OFFSET")))
trace=False
class Operand(object):
  def getVal(self,emu):
    if self.type=="const":
      return self.value
    elif self.type=="register":
      return emu.readRegister(self.value)
    elif self.type=="stackvar":
      return emu.readStackValue(int(self.value,0),self.length,False)
    elif self.type=="memconst":
      return 0 #need implementation?
  def __hash__(self):
    return hash((self.type, self.value))
  def __eq__(self, other):
    return (self.type, self.value) == (other.type, other.value)
  def __ne__(self, other):
    return not(self == other)
  def __init__(self,instr,num):
   self.type="unknown"
   if instr is None:
     return
   if num>=instr.getNumOperands():
     return
   tp=instr.getOperandType(num)
   objlist=instr.getOpObjects(num)
   ln=len(objlist)
   if ln==0:
     return
   if tp&OperandType.SCALAR: #const
     self.type="const"
     self.value=int(str(objlist[0]),16)
     return
   if tp&OperandType.REGISTER and len(objlist)==1: #pure register
     self.type="register"
     self.value=str(objlist[0])
     return
   if len(objlist)==2 and str(objlist[0])=="RSP":
     self.type="stackvar"
     self.value="0x{:x}".format(int(str(objlist[1]),0))
     self.offset=int(str(objlist[1]),0)
     self.len=1
     oprep=instr.getDefaultOperandRepresentation(num)
     if "xword" in oprep:
       self.length=16
     elif "qword" in oprep:
       self.length=8
     elif "dword" in oprep:
       self.length=4
     elif "word ptr" in oprep:
       self.length=2
     elif "byte ptr" in oprep:
       self.length=1
     return
   if len(objlist)==2 and tp&OperandType.DYNAMIC and tp&OperandType.ADDRESS : #dword ptr [RCX + -0x4] 
     self.type="memconst"
     self.value=str(objlist[1])
     self.olist=objlist
     return
   if len(objlist)==2 and str(objlist[0])=="GS":
     self.type="debugho"
     self.value="__0x{:x}".format(int(str(objlist[1]),0))
     return
   if len(objlist)==3 and isinstance(objlist[0],Register): #not quite correct, but. uff
     self.type="register"
     self.value=str(objlist[0])
     return
   logger.warning("{} {:x} {} needs operand implementation {}".format(instr,tp,num,objlist))

#not sure why only these are missing.
def pshuflw(emu,instr):
  if instr is None: return
  if instr.getNumOperands()!=3: return
  reg_into=Operand(instr,0)
  reg_from=Operand(instr,1)
  shuf=Operand(instr,2)
  if reg_into.type!="register" or reg_from.type!="register" or shuf.type!="const" :
    raise 33
  fr=emu.readRegister(reg_from.value)
  imm=shuf.value
  to=(fr&0xffffffffffffffff0000000000000000)
  to+=(fr>> (imm&4)*16 )&0xffff
  to+=((fr>> ( (imm>>2) & 4)*16 )&0xffff)<<16
  to+=((fr>> ( (imm>>4) & 4)*16 )&0xffff)<<32
  to+=((fr>> ( (imm>>8) & 4)*16 )&0xffff)<<48
  emu.writeRegister(reg_into.value,to)
  skip(emu)
def pmovmskb(emu,instr):
  if instr is None: return
  if instr.getNumOperands()!=2: return
  reg_into=Operand(instr,0)
  reg_from=Operand(instr,1)
  if reg_into.type!="register" or reg_from.type!="register":
    raise 34
  fr=emu.readRegister(reg_from.value)
  cnt=1
  val=0
  for bt in range(16):
    idir=int((fr&(1<<(8*cnt-1)))!=0)
    val |= (idir<<bt)
    cnt+=1
  emu.writeRegister(reg_into.value,val)
  skip(emu)

def dumpParameters(emu,num):
   pars=[emu.readRegister("RCX"),emu.readRegister("RDX"),emu.readRegister("R8"),emu.readRegister("R9")]
   if num>4:
    co=0x28
    esp=emu.readRegister("ESP")
    for a in range(num-4):
      pars.append(readULL(emu,getAddress(esp+co)))
      co+=8
   for a in range (num):
     logger.info("Param_{}: {:x}".format(a+1,pars[a]))
     
def writeRegister(emu,reg,fl):
  nm=reg.getName()
  ln=reg.getMinimumByteSize()
  if ln >8:
   ln=16
  elif ln>4:
   ln=8
  elif ln >2:
   ln=4
  else:
   ln=2
  fl.write(struct.pack("<H", len(nm)))
  fl.write(nm.encode("ascii"))
  fl.write(struct.pack("<H", ln))
  val=emu.readRegister(nm)
  if ln==16:
   fl.write(struct.pack("<Q", (val>>64)&0xffffffffffffffff ))
   fl.write(struct.pack("<Q", val&0xffffffffffffffff))
  elif ln==8:
   fl.write(struct.pack("<Q", val&0xffffffffffffffff))
  elif ln==4:
   fl.write(struct.pack("<I", val&0xffffffff))
  else:
   fl.write(struct.pack("<H", val&0xffff))
   
def writeMemoryChunk(emu,start,ln,fl):
  fl.write(struct.pack("<Q",start))
  fl.write(struct.pack("<Q",ln))
  if ln>0:
    mbuf=emu.readMemory(getAddress(start),ln)
    fl.write(mbuf)

def writeSnapshot(emu,fl):
  global mem, rspStart, currentProgram
  excl=set(["contextreg"])
  br=set([e.getBaseRegister() for e in getProgramRegisterList(currentProgram) if e.getBaseRegister().getName() not in excl])
  rsp=emu.readRegister("RSP")
  fl.write(struct.pack("<I",len(br)))
  for reg in br:
   writeRegister(emu,reg,fl)
  writeMemoryChunk(emu,mem.start,mem.curpoint-mem.start,fl)
  if rsp<=rspStart:
    writeMemoryChunk(emu,rsp,rspStart-rsp+8,fl)
  for blk in currentProgram.getMemory().getBlocks():
    writeMemoryChunk(emu,blk.getStart().getOffset(),blk.getSize(),fl)
    
def readRegister(emu,fl):
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
  if nm!= "contextreg":
   emu.writeRegister(nm,val)
  return True
def readMemoryChunk(emu,fl,setmem=False):
  #start,ln,
  global mem
  dt=fl.read(8)
  if len(dt)<8: return False
  start=struct.unpack("<Q",dt)[0]
  dt=fl.read(8)
  if len(dt)<8: return False
  ln=struct.unpack("<Q",dt)[0]
  if ln>0:
    dat=fl.read(ln)
    if len(dat)<ln: return False
    emu.writeMemory(getAddress(start),dat)
  if setmem:
    mem.start=start
    mem.curpoint=start+ln
  return True
def readSnapshot(emu,fl):
  global mem, rspStart
  numreg=struct.unpack("<I",fl.read(4))[0]
  for i in range(numreg):
    if not readRegister(emu,fl):
      logger.warning("Corrupt snapshot: not enough registers")
      return
  mset=True
  while readMemoryChunk(emu,fl,mset):
    mset=False

import gzip
import os
basedir="./"
def saveSnapshot(emu,name):
  global basedir
  fname=os.path.join(basedir,name)
  with gzip.open(fname, 'wb',compresslevel=8) as f:
    writeSnapshot(emu,f)

def loadSnapshot(emu,name):
  global basedir
  fname=os.path.join(basedir,name)
  with gzip.open(fname, 'rb') as f:
    readSnapshot(emu,f)
class Permutator(object): #for 256-byte objects...
  def __init__(self, grabAddr,tableReg,ptrReg,name=None,cntd=31):
    self.grabAddr=grabAddr
    self.table=None
    self.tableReg=tableReg
    self.ptrReg=ptrReg
    self.countdown=0
    self.name=name
    self.cntd=cntd
  def grab(self, emu,addr):
    if addr==self.grabAddr:
      if self.table is None:
        print("Getting table from  {}".format(self.tableReg))
        if isinstance(self.tableReg, (int,long)):
         rg=self.tableReg
        else:
         rg=emu.readRegister(self.tableReg)
        self.table=[]
        for a in range(32):
          self.table.append(emu.readMemoryByte(getAddress(rg+a)))
      if self.countdown>0:
       self.countdown-=1
      else:
        #print("Grabbing at {}".format(addr))
        if isinstance(self.ptrReg,list):
         if len(self.ptrReg)==2:
          dataAddr=emu.readRegister(self.ptrReg[0])+self.ptrReg[1]
         else:
          indirAddr=emu.readRegister(self.ptrReg[0])+self.ptrReg[1]
          dataAddr=readULL(emu,getAddress(indirAddr))
        elif isinstance(self.ptrReg,(int,long)):
         dataAddr=self.ptrReg
        else:
         dataAddr=emu.readRegister(self.ptrReg)
        val=0
        for a in range(32):
          dlt=readULL(emu,getAddress(dataAddr+8*self.table[a]))
          val=val+dlt*(1<<(64*a))
        self.countdown=self.cntd
        if self.name is None:
          logger.info("Grabbed at {}: {:x}".format(self.grabAddr,val))
        else:
          logger.info("Grabbed {} at {}: {:x}".format(self.name,self.grabAddr,val))
class BCollector(object):
  def __init__(self,name,startAddr,collectAddr,collectA,collectB,endAddr,paraCol=False):
    self.name=name
    self.startAddr=getAddress(startAddr)
    self.endAddr=getAddress(endAddr)
    self.collectAddr=getAddress(collectAddr)
    self.isCollecting=False
    self.collectA=collectA
    self.a=0
    self.collectB=collectB
    self.b=0
    self.cnt=0
    self.cntb=0
    self.paracol=paraCol
  def emget(self,emu, coll):
    lc=len(coll)
    if lc ==1:
     if isinstance(coll[0],int):
       return readULL(emu,getAddress(coll[0]))
     else:
       return emu.readRegister(coll[0])
    elif lc==2: #[reg+const]
     addr=emu.readRegister(coll[0])+coll[1]
     return readULL(emu,getAddress(addr))
    elif lc==3: #[reg+reg*const]
     addr=emu.readRegister(coll[0])+emu.readRegister(coll[1])*coll[2]
     #logger.info("Cll: {:x} {:x} {:x}".format(emu.readRegister(coll[0]),emu.readRegister(coll[1]),addr))
     return readULL(emu,getAddress(addr))
    elif lc==4: #[reg+reg*const+c2]
     addr=emu.readRegister(coll[0])+emu.readRegister(coll[1])*coll[2]+coll[3]
     return readULL(emu,getAddress(addr))
    elif lc==5: # ["RSP",40,"RAX",8,"indir"]
     addr=emu.readRegister(coll[0])+coll[1]
     addr2=readULL(emu,getAddress(addr))+emu.readRegister(coll[2])*coll[3]
     return readULL(emu,getAddress(addr2))
  def collect(self,emu,addr):
    if addr==self.startAddr:
      self.a=0
      self.b=0
      self.cntb=0
      self.cnt=0
      self.isCollecting=True
    elif addr==self.endAddr:
      logger.info("Collected as {} ,a : {:x}".format(self.name,self.a))
      logger.info("Collected as {} ,b : {:x}".format(self.name,self.b))
      logger.info("Collection rounds as {} , {}".format(self.name,self.cnt))
      self.a=0
      self.b=0
      self.cnt=0
      self.isCollecting=False
    elif addr==self.collectAddr and self.isCollecting:
      da=self.emget(emu,self.collectA)
      if not self.paracol:
       db=self.emget(emu,self.collectB)
      ml=(1<<(64*self.cnt))
      self.a+=ml*da
      if not self.paracol:
       self.b+=ml*db
      self.cnt+=1
    elif self.isCollecting and self.paracol and self.cntb<32 and addr>self.startAddr and addr<self.endAddr:
     instr=getInstructionAt(addr)
     if instr.getMnemonicString()=="MUL":
      db=self.emget(emu,self.collectB)
      ml=(1<<(64*self.cntb))
      self.b+=ml*db
      self.cntb+=1
snc=528
def dumpBuffer(emu,offs_addr,ln):
  dl=emu.readMemory(getAddress(offs_addr),ln)
  dst=""
  for a in dl:
    if a<0: a+=256
    dst+="{:02X}".format(a)
  logger.info("{}".format(dst))
def runModule(start,lSnapshot=None):
  global trace, basedir, snc
  cur_fun=getFunctionContaining(start)
  mainFunctionEntryLong = int("0x{}".format(cur_fun.getEntryPoint()), 16)
  emu.writeRegister(emu.getPCRegister(), mainFunctionEntryLong)
  #for nl in range(nnl):
  subN=False
  nnn=0
  fff=0
  ncnt=0
  cnt=0
  #stack=emu.readRegister("RSP")
  fname=None
  if lSnapshot is not None:
    if os.path.isfile(lSnapshot):
     fname=lSnapshot
    elif os.path.isfile(os.path.join(basedir,lSnapshot)):
     fname=os.path.join(basedir,lSnapshot)
    else:
     logger.warning("{} is not correct file name".format(lSnapshot))
  if fname is None:
    EmuPush(emu,0xfafadeadbeef)
  else:
    loadSnapshot(emu,fname)
  snapcnt=0
  #precoll= BCollector("MbSubtr",0x18017b07c,0x18017b0eb,["R14"],["RCX","RAX",8],0x18017b13f)
  #ncoll=BCollector("SubN",0x18017b140,0x18017b1e5,["RDI"],["RAX"],0x18017b24b)
  #vcoll=BCollector("VC",0x18016dc81,0x18016dcb5,["RCX"],["RCX"],0x18016dcdb)
  #pcoll=BCollector("Plus",0x18017b367,0x18017b397,["R14","RAX",8],["R15","RAX",8],0x18017b3ff)
  #ucoll=BCollector("Upper",0x18017c4d2,0x18017c52a,["RAX"],["R12","RCX",8],0x18017d326,False)
  #yacoll=BCollector("YetAnother",0x18017b513,0x18017b578,["RAX"],["R14","RCX",8],0x18017c2f5,False)
  #hm1coll=BCollector("HasMulAdd",0x18016dd26,0x18016dd87,["RAX"],["R13","RCX",8],0x18016ebb4,False)
  #hm2coll=BCollector("HasMulAdd2",0x18016ec3f,0x18016eca5,["RAX"],["R12","RCX",8],0x18016fab9,False)
  #mnscoll=BCollector("Subtractor",0x18017d4ac,0x18017d54a,["R12"],["RAX"],0x18017d598)
  # add permutators to track Bignum manipulation. Each one slows down execution, so use with care?
  prms=[Permutator(getAddress(0x18017c373),"RSI","R14"),
        Permutator(getAddress(0x18017c505),"RBX","R12"),
        Permutator(getAddress(0x18017b0c7),"RDI","R15"),
        #MaybeImportantSubtraction
        Permutator(getAddress(0x18017b0eb),0x180bb7258,"R15","SubtractionA"), #maybesubtraction
        Permutator(getAddress(0x18017b0eb),0x180bb7258,["RSP", 32,"rd"],"SubtractionB"), #maybesubtraction
        #SubN - moved to next function that actually finalized modN operation, it seems. 
        Permutator(getAddress(0x18017b33d),0x180bb7258,["RSP", 32,"rd"],"ModN",0),
        #VC - maybe first op?
        Permutator(getAddress(0x18016dce0),0x180bb7258,["RSP", 0xae20],"VC"), #VC
        #LooksSum: only args?
        Permutator(getAddress(0x18017b367),0x180bb7258,"R15","SumA",0),#sum?
        Permutator(getAddress(0x18017b367),0x180bb7258,"R14","SumB",0),#sum?
        #Plum - only result
        Permutator(getAddress(0x18017b4ba),0x180bb7258,"R13","PostSum",0),#dealing with overflow?
        #"Upper" multiply. Looks like square, honestly
        Permutator(getAddress(0x18017d313),0x180bb7258,["RSP", 48,"rd"],"Upper",0),
        #YetAnother: get args:
        Permutator(getAddress(0x18017b513),0x180bb7258,["RSP", 0x60,"rd"],"MulA",0),#mul?
        Permutator(getAddress(0x18017b513),0x180bb7258,["RSP", 56,"rd"],"MulB",0),#mul?
        #Main(?) func has several multiplies separate
        Permutator(getAddress(0x18016dd26),0x180bb7258,["RSP", 0xab20],"Main1A",0),
        Permutator(getAddress(0x18016dd26),0x180bb7258,0x180650ef0,"Main1B",0),
        
        Permutator(getAddress(0x18016ec3f),0x180bb7258,["RSP", 0xaa20],"Main2A",0),
        Permutator(getAddress(0x18016ec3f),0x180bb7258,0x180651450,"Main2B",0),
        #CopyLnum
        Permutator(getAddress(0x18017c39f),0x180bb7258,"R15","Copy",0),
        # Second func (decrypt?)
        Permutator(getAddress(0x180148eea),0x180bb70d4,"R15","S_SubtractionA"), #maybesubtraction
        Permutator(getAddress(0x180148eea),0x180bb70d4,["RSP", 32,"rd"],"S_SubtractionB"), #maybesubtraction
        #main
        Permutator(getAddress(0x180144477),0x180bb70d4,["RSP", 0xb000],"S_Main1A",0),
        Permutator(getAddress(0x180144477),0x180bb70d4,0x18064e750,"S_Main1B",0),
        #nmodulo
        Permutator(getAddress(0x1801491ab),0x180bb70d4,["RSP", 32,"rd"],"S_ModN",0),
        #sum
        Permutator(getAddress(0x1801491e5),0x180bb70d4,"R15","S_SumA",0),#sum?
        Permutator(getAddress(0x1801491e5),0x180bb70d4,"R14","S_SumB",0),#sum?
        #sumres
        Permutator(getAddress(0x180149328),0x180bb70d4,"R13","PostSum",0),#dealing with overflow?
        
        
        Permutator(getAddress(0x18017d50a),"RSI","RCX"),
        #Permutator(getAddress(0x18017d535),"RDI","RCX"), is xored??
        #AdcUser??
        Permutator(getAddress(0x18014b378),"RSI","RCX"),
        #SumAdc??
        Permutator(getAddress(0x180149205),"RDI","R15"),
        Permutator(getAddress(0x180149228),"RDI","R14"),
        #Another minusN?
        Permutator(getAddress(0x180149013),"RBX","RCX"),
        #Mul is suspect
        Permutator(getAddress(0x1801444a6),"R13",["RSP", 0xb000]),        
        ]
  #prms=[]

  coutp=None
  
  cclen=None
  #very detailed trace, good for spotting small discrepancies but slow and verbose
  superTrace=False
  while True:
    executionAddress = emu.getExecutionAddress()
    if executionAddress==getAddress(0xfafadeadbeef):
      logger.info("Probably return ")
      break
    if executionAddress==getAddress(0x18016dc81):
      rsp=emu.readRegister("RSP")+0xb120
      logger.info("Preload")
      dumpBuffer(emu,rsp,0x402)
    if executionAddress==getAddress(0x18016d323):
      rsi=emu.readRegister("RSI")
      logger.info("Param4")
      dumpBuffer(emu,rsi,0x40e)
      
    #if executionAddress==getAddress(0x18016d42d):
      #rsi=emu.readRegister("RSP")+0x1120
      #logger.info("Altering local4")
      #for i in range(4):
      #  emu.writeMemoryValue(getAddress(rsi+i),1,0)
     
    #if executionAddress==getAddress(0x18016d328):
      #rsi=emu.readRegister("RDI")
      #logger.info("Parpost")
      #dumpBuffer(emu,rsi,0x40e)
      

    if executionAddress==getAddress(0x18016db2a):
      rsp=emu.readRegister("RSP")+0xab20
      logger.info("collector")
      dumpBuffer(emu,rsp,0x10)

    if executionAddress==getAddress(0x18016b07e): #ConstUser
      cnst=emu.readRegister("RCX")
      inp1=emu.readRegister("RDX")
      inp2=emu.readRegister("R8")
      output=emu.readRegister("R9")
      coutp=output
      offset = (cnst & 0x3fffff)
      ln=(cnst >> 0x24) & 0x3fff
      ln2=cnst >> 0x32
      flen=ln+ln2
      cclen=flen
      if ln>0:
       logger.info("Constant of offset {:x} len {} len2 {}".format(offset,ln,ln2))
       logger.info("Constant input 1: ")
       dumpBuffer(emu,inp1,flen)
       logger.info("Constant input 2: ")
       dumpBuffer(emu,inp2,flen)
       
    if executionAddress==getAddress(0x18016b147):
      if coutp is not None and cclen>0:
        logger.info("Constant output: ")
        dumpBuffer(emu,coutp,cclen)
        coutp=None
        cclen=0
        
    if executionAddress==getAddress(0x1801722bb):
      esp=emu.readRegister("RSP")+0x50e20
      logger.info("Austack ");
      dumpBuffer(emu,esp,0x5d0)
    if executionAddress==getAddress(0x180172624):
      esp=emu.readRegister("RSP")+0x4faf0
      logger.info("Austack 2");
      dumpBuffer(emu,esp,0x5d0)

    if executionAddress==getAddress(0x18017df74):
      logger.info("Much bollockry reached")
      dumpParameters(emu,5)
      saveSnapshot(emu,"bollockrySnap.gz")

    for prm in prms:
      prm.grab(emu,executionAddress)
      
    if executionAddress==getAddress(0x1801f539b):   
      saveSnapshot(emu,"snap1801f539b_{}.gz".format(snc))
      snc+=1
    if executionAddress==getAddress(0x18016dbc1):
      print(emu.readRegister("ECX"))
      #print(CALLED)
    if executionAddress==getAddress(0x1800779a0):   
      saveSnapshot(emu,"Walltimeindir1801f539b_{}.gz".format(snc))
      snc+=1
      logger.info("Walltimeindir saved")
    if executionAddress==getAddress(0x180072a58):   
      saveSnapshot(emu,"Irrel180072a58_{}.gz".format(snc))
      snc+=1
      logger.info("Irrel entry saved")
    if executionAddress==getAddress(0x18016d24d):   
      saveSnapshot(emu,"Hasmulret18016d24d_2_{}.gz".format(snc))
      snc+=1
      logger.info("Mulret entry saved")

    if executionAddress==getAddress(0x180057514):
      logger.info("Sussery reached")
      dumpParameters(emu,2)
      saveSnapshot(emu,"susserySnap.gz")
      #trace=True
      
    if executionAddress==getAddress(0x1801a3556): 
       saveSnapshot(emu,"paramBuggery.gz")
       
    if executionAddress==getAddress(0x180291490): #RSA encrypt?
       rcx=emu.readRegister("RCX")
       nptr=readULL(emu,getAddress(rcx))
       eptr=readULL(emu,getAddress(rcx+8))
       dptr=readULL(emu,getAddress(rcx+16))
       logger.info("At RSA encrypt: {:x} {:x} {:x}".format(nptr,eptr,dptr))
       saveSnapshot(emu,"rsaSnap.gz")
       
    if executionAddress==getAddress(0x1801d6780):
      rax=emu.readRegister("ESI")
      rsp=emu.readRegister("RSP")
      logger.info("Should be esi: {:x} at {:x}+".format(rax,rsp+0xc8))
    if executionAddress==getAddress(0x18017e3b0):
      saveSnapshot(emu,"Longstringproc_{}.gz".format(snc))
      snc+=1
    if executionAddress==getAddress(0x1801720e0):
      saveSnapshot(emu,"ManyMults1801720e0_{}.gz".format(snc))
      snc+=1

    if executionAddress==getAddress(0x1801722bb):
      dat=emu.readMemory(getAddress(emu.readRegister("RSP")+0x70),0x5a0)
      dst=""
      for a in dat:
        if a<0: a+=256
        dst+="{:02X}".format(a)
      #print("{:x}".format(eadr))
      logger.info("Buffer: {}".format(dst))
      dat=emu.readMemory(getAddress(emu.readRegister("RSP")+0x50e20),0x5a0)
      dst=""
      for a in dat:
        if a<0: a+=256
        dst+="{:02X}".format(a)
      logger.info("Buffer2: {}".format(dst))

    if executionAddress==getAddress(0x1801a35d0):
      rsp=emu.readRegister("RSP")+0x33a0
      logger.info("Bollocks3:")
      dumpBuffer(emu,rsp,0x5a*4)
    if executionAddress==getAddress(0x18017a771):
     superTrace=True
    if superTrace:
      ein=getInstructionAt(executionAddress)
      xmm0=emu.readRegister("XMM0")
      xmm1=emu.readRegister("XMM1")
      xmm2=emu.readRegister("XMM2")
      xmm3=emu.readRegister("XMM3")
      xmm4=emu.readRegister("XMM4")
      xmm5=emu.readRegister("XMM5")
      xmm6=emu.readRegister("XMM6")
      xmm7=emu.readRegister("XMM7")
      xmm8=emu.readRegister("XMM8")
      xmm9=emu.readRegister("XMM9")
      xmm10=emu.readRegister("XMM10")
      logger.info("###############")
      logger.info("Address: 0x{} ({})".format(executionAddress, ein))
      logger.info("Xmm0 ={:x}  Xmm1 ={:x}  Xmm2 ={:x}  Xmm3 ={:x}  ".format(xmm0,xmm1,xmm2,xmm3))
      logger.info("Xmm4 ={:x}  Xmm5 ={:x}  Xmm6 ={:x}  Xmm7 ={:x}  ".format(xmm4,xmm5,xmm6,xmm7))
      logger.info("Xmm8 ={:x}  Xmm9 ={:x}  Xmm10={:x}".format(xmm8,xmm9,xmm10))
      regs=["RAX","RBX","RCX","RDX","R8","R9","R10","R11","R12","R13","R14","R15","RBP","RSI","RDI"]
      rt=""
      for r in regs:
        val=emu.readRegister(r)
        rt=rt+"{}: {:x}   ".format(r,val)
      logger.info("Registers: {}".format(rt))

    if executionAddress==getAddress(0x18017e440):
      saveSnapshot(emu,"Longstring_nearsha_{}.gz".format(snc))
      snc+=1
      addr=emu.readRegister("R8")
      dat=emu.readMemory(getAddress(addr),0x1c8)
      dst=""
      for a in dat:
        if a<0: a+=256
        dst+="{:02X}".format(a)
      logger.info("Buffer before: {}".format(dst))
    if executionAddress==getAddress(0x18017e454):
      saveSnapshot(emu,"Longstring_postsha_{}.gz".format(snc))
      snc+=1
      addr=emu.readRegister("RBP")
      dat=emu.readMemory(getAddress(addr),0x1c8)
      dst=""
      for a in dat:
        if a<0: a+=256
        dst+="{:02X}".format(a)
      logger.info("Buffer After: {}".format(dst))
    if executionAddress==getAddress(0x18017e473):
      saveSnapshot(emu,"Longstring_postfun_{}.gz".format(snc))
      snc+=1
      addr=emu.readRegister("RDI")
      dat=emu.readMemory(getAddress(addr),0x200)
      dst=""
      for a in dat:
        if a<0: a+=256
        dst+="{:02X}".format(a)
      logger.info("Buffer other: {}".format(dst))
    
    #if executionAddress==getAddress(0x1802c8d56):
    #  rax=emu.readRegister("RAX")
    #  logger.info("Index: {:x}".format(rax))
    #if executionAddress==getAddress(0x18017b4cb):
    #  rcx=emu.readRegister("RCX")
    #  dat=emu.readMemory(getAddress(rcx),256)
    #  logger.info("First array: {}".format(dat))
    if executionAddress==getAddress(0x1801d67e4):
      rsp=emu.readRegister("RSP")
      strng=readULL(emu,getAddress(rsp+0xc0))
      dat=emu.readMemory(getAddress(strng),91)
      logger.info("Shouldreallybestring: {:x} dat :{}".format(strng,dat))
    if executionAddress==getAddress(0x1802ca455):
      rax=emu.readRegister("RAX")
      ptr=readULL(emu,getAddress(rax))
      sz=readULL(emu,getAddress(rax+8))
      cap=readULL(emu,getAddress(rax+16))
      logger.info("Shouldbestring: {:x} sz: {} cap : {:x}".format(ptr,sz,cap))
      stdat=emu.readMemory(getAddress(ptr),90)
      logger.info("Shouldbestringdata: {}".format(stdat))
    if executionAddress==getAddress(0x1802c8af8) or executionAddress==getAddress(0x1802cbf37):
     rcx=emu.readRegister("RCX")
     rdx=emu.readRegister("RDX")
     r8=emu.readRegister("R8")
     r9=emu.readRegister("R9")
     logger.info("Thishere: {} {} {} {}".format(rcx,rdx,r8,r9))
     
    if executionAddress in dict:
      logger.info("Substituting {}".format(executionAddress))
      dict[executionAddress](emu)
    else:
      ein=getInstructionAt(executionAddress)
      cnt+=1
      snapcnt+=1
      if cnt>100000:
       cnt=0
       logger.info("Address: 0x{} ({})".format(executionAddress, ein))
       logger.info("RAX: {:x} RCX: {:x} RBP: {:x}".format(emu.readRegister("RAX"),emu.readRegister("RCX"),emu.readRegister("RBP")))
      if snapcnt>1000000:
        saveSnapshot(emu,"Periodic2_{}.gz".format(snc))
        snc+=1
        snapcnt=0
        logger.info("Periodic snapshot {} saved".format(snc-1))
      con=getCallOtherName(ein)
      if con is not None:
        if con == "pshuflw":
         pshuflw(emu,ein)
        elif con == "pmovmskb":
         pmovmskb(emu,ein)
        else:
         logger.info("Skipping: {}".format(ein)) 
         skip(emu)
         continue
      if trace:
       logger.info("Address: 0x{} ({})".format(executionAddress, ein))
      elog=False
      if elog:
          if isCallInstruction(ein):
            logger.info("CAddress: 0x{} ({})".format(executionAddress, ein))
            logger.info("RAX: {:x} RCX: {:x} RBP: {:x}".format(emu.readRegister("RAX"),emu.readRegister("RCX"),emu.readRegister("RBP")))
            logger.info("RDX: {:x} RDI: {:x} RBX: {:x}".format(emu.readRegister("RDX"),emu.readRegister("RDI"),emu.readRegister("RBX")))
            logger.info("R8 : {:x} R9 : {:x} R15: {:x}".format(emu.readRegister("R8"),emu.readRegister("R9"),emu.readRegister("R15")))
          if isReturn(ein):
            logger.info("Returning: 0x{}  {:x}".format(executionAddress, emu.readRegister("RAX")))

sn4file=os.path.join(basedir,"Longstringproc_620.gz") #from 250...586  Periodic2_1230.gz Hasmulret18016d24d_602.gz ManyMults1801720e0_1206.gz
if os.path.isfile(sn4file): 
  snc=1359
  #trace=True
  runModule(initCdm,sn4file)
else:
    runModule(initCdm)
    createCdmInstance=getAddress(0x1800010a0)
    emu.writeRegister("RCX",10)
    keys = "com.widevine.alpha"#"com.widevine.alpha"
    keyptr=get_cptr(emu,keys)
    emu.writeRegister("RDX",keyptr)
    emu.writeRegister("R8",len(keys))
    emu.writeRegister("R9",0xf0000)
    EmuPush(emu,0)
    logger.info("Running CreateInstance")
    runModule(createCdmInstance)
    saveSnapshot(emu,"snapshot1.gz")
    cdmInst=emu.readRegister("RAX")
    logger.info("Instance: {:x}".format(cdmInst))
    #vtable[0]=Initialize(true, false, false);
    #cdmVtableP=readULL(emu,getAddress(cdmInst))
    cdmVtable=readULL(emu,getAddress(cdmInst))
    logger.info("Vtable: {:x}".format(cdmVtable))
    cdmInitialize=readULL(emu,getAddress(cdmVtable))
    logger.info("cdmInitialize: {:x}".format(cdmInitialize))
    emu.writeRegister("RCX",cdmInst)
    logger.info("Running Initialize")
    #trace=True
    emu.writeRegister("RDX",1)
    emu.writeRegister("R8",0)
    emu.writeRegister("R9",0)
    runModule(getAddress(cdmInitialize))
    saveSnapshot(emu,"snapshot2.gz")
     #ContentDecryptionModule_10* cdm =(ContentDecryptionModule_10 *) create(10, keys.c_str(), keys.length(), 
     #GetDummyHost, (void*) msg);
    #logger.info("First compare: {}".format(readULL(emu,getAddress(cdmInst+0x92))))
    creses=readULL(emu,getAddress(cdmVtable+3*8))#CreateSessionAndGenerateRequest
    logger.info("CreateSessionAndGenerateRequest: {:x}".format(creses))
    logger.info("Running CreateSession")
    emu.writeRegister("RCX",cdmInst)
    emu.writeRegister("RDX",11)
    emu.writeRegister("R8",0)
    emu.writeRegister("R9",0)
    idata= [0, 0, 0, 91, 112, 115, 115, 104, 
            0, 0, 0, 0, 
            237, 239, 139, 169, 121, 214, 74,206, 
            163, 200, 39, 220, 213, 29, 33, 237, 
            0, 0, 0, 59, 
            8,  1, 18, 16, 235, 103, 106, 187, 203, 52,
                        94, 150, 187, 207, 97, 102, 48, 241, 163, 218, 26, 13,
                       119, 105, 100, 101, 118, 105, 110, 101, 95, 116, 101,
                      115, 116, 34, 16, 102, 107,106, 51, 108, 106, 97, 83,
                      100, 102, 97, 108, 107, 114, 51, 106, 42, 2, 72, 68,50, 0]
    initdata=listToMem(emu,idata)
    EmuPush4(emu, 0)
    EmuPush4(emu, 91)
    rsp=emu.readRegister("RSP")
    logger.info("Pushed len to {:x}".format(rsp))

    EmuPush(emu, initdata)
    rsp=emu.readRegister("RSP")
    logger.info("Pushed data to {:x}".format(rsp))

    EmuPush(emu, 0)
    EmuPush(emu, 0)
    EmuPush(emu, 0)
    EmuPush(emu, 0)
    runModule(getAddress(creses))


  