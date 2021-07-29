# Simple attempt to follow obfuscated code.  Mostly copied from SwitchOverride.java. Incomplete, please only use as reference.
#@author Satsuoni
#@category Deobfuscation
#@keybinding 
#@menupath 
#@toolbar 


from binascii import hexlify
import logging
from ghidra.app.emulator import EmulatorHelper
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

import sys

DATA_FILE="runData.json"
logger = logging.getLogger("")
logger.setLevel(logging.DEBUG)
handler1=logging.StreamHandler(sys.stdout)
# from StackOverflow
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
handler2=logging.FileHandler("testlog.log", mode='w', encoding="utf-8")
handler2.setFormatter(formatter)
logger.addHandler(handler1)
logger.addHandler(handler2)

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    
def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers
    
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
listing = currentProgram.getListing()

logger.info("Starting working on {}".format(name))
def getPossibleConstAddressFromInstruction(instr):
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.COPY:
      inp=code.getInputs()[0]
      if inp.size==8 and inp.isConstant():
       return getAddress(inp.getOffset())
  return None

def isReturn(instr):
  if instr is None:
    return False
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.RETURN:
      return True
  return False

def isComputedBranchInstruction( instr):
    if instr is None:
        return False
    flowType = instr.getFlowType()
    if flowType == RefType.COMPUTED_JUMP:
        return True
    if (flowType.isCall()):
        #is it a callfixup?
        referencesFrom = instr.getReferencesFrom()
        for reference in referencesFrom:
            if reference.getReferenceType().isCall():
                func = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress())
                if func is not None and func.getCallFixup() is not None:
                    return True
    return False 
    
def isCallInstruction(instr):
    if instr is None:
        return False
    flowType = instr.getFlowType()
    if flowType.isCall():
      return True
    return False
    
def isCallOther(instr):
  if instr is None:
    return False
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.CALLOTHER:
      return True
  return False
  
def getCondmoveInstruction(instr):
   if instr is None:
     return None
   raw_pcode = instr.getPcode()
   for entry in raw_pcode:
     if entry.getOpcode()==PcodeOp.CBRANCH:
        addr=entry.getInput(0)
        if addr is None: continue
        if addr.size==8 :
           maybeaddr=getAddress(addr.getOffset())
           nextInstr=instr.getNext()
           if nextInstr is None:
            return None
           if nextInstr.getAddress()==maybeaddr:
             return (instr.getAddress(),instr.getDefaultOperandRepresentation(0),
                     instr.getDefaultOperandRepresentation(1))
   return None
   
def getPotentialJtableAccess(instr): #use mnemonic? movsx(d), add, jmp, returns None or (jtableReg,offsetReg,jumpAddr)
   if instr is None:
     return False
   mnem=instr.getMnemonicString().lower()
   if "movsx" in mnem:
     nxt=instr.getNext()
     if nxt is None: return None
     nx=nxt.getMnemonicString().lower()
     if not "add" in nx: return None
     nxt=nxt.getNext()
     if nxt is None: return None
     if isComputedBranchInstruction(nxt):
       objects=instr.getOpObjects(1)
       if len(objects)!=3 or int(str(objects[2]),0)!=4:
         return None
       return (objects[0],objects[1],nxt.getAddress())
   return None
   
def skip(emu):
  executionAddress = emu.getExecutionAddress() 
  instr=getInstructionAt(executionAddress)
  nextInstr=instr.getNext()
  lval = int("0x{}".format(nextInstr.getAddress()), 16)
  emu.writeRegister(emu.getPCRegister(), lval)

#there can be several cmove in one code step...


class Branch(object):
  def __init__(self, addr, to, frm):
    self.address=addr
    self.true=frm
    self.false=to
    self.target=to
    self.isTrueTaken=False
    self.isFalseTaken=False
    self.trueIndex=None
    self.falseIndex=None
    self.lastTaken=None
  def take(self,pth,emu):
    if emu.getExecutionAddress() !=self.address:
      logger.warning("Trying to take branch {} at address {}".format(self.address,emu.getExecutionAddress()))
      return 
    if pth:
      val=emu.readRegister(self.true)
    else:
      val=emu.readRegister(self.false)
    emu.writeRegister(self.target,val)
    self.lastTaken=pth
    skip(emu)
  def registerOutput(self,output): #output is a tuple (type, value)
    if self.lastTaken is None:
      logger.warning("Trying to write output for branch {} that was not triggered".format(self.address))
      return
    if self.lastTaken:
      if self.isTrueTaken:
        if self.trueIndex[0]!=output[0] or self.trueIndex[1]!=output[1]:
          logger.warning("Trying to overwrite true output for branch {} ".format(self.address))  
          return
      else:
        self.isTrueTaken=True
        self.trueIndex=output
    else:
      if self.isFalseTaken:
        if self.falseIndex[0]!=output[0] or self.falseIndex[1]!=output[1]:
          logger.warning("Trying to overwrite false output for branch {} ".format(self.address))  
          return
      else:
        self.isFalseTaken=True
        self.falseIndex=output
  def hasUntakenPaths(self):
     return not (self.isFalseTaken and self.isTrueTaken)
  def getNextUntaken(self):
     if not self.isFalseTaken: return False
     if not self.isTrueTaken: return True
     return None
  def getExpectedOutput(self):
    if self.lastTaken is None:
      return None
    if self.lastTaken:
      return self.trueIndex
    else:
      return self.falseIndex
class BranchBox(object):
  def __init__(self,index):
    self.branches=[]
    self.curbranch=None
    self.trace=None
    self.index=index # number in obfuscated jump
    self.pathTaken=[]
    self.pathToBox=[] #a path to retrace if you want to get to this box, I guess
    logger.info("Registering new branch box at 0x{}".format(index))
  def hasUntakenPaths(self):
    for br in self.branches:
      if br.hasUntakenPaths():
        return True
    return False
  def registerBranch(self,condmove): # tuple..
    #logger.info("Register branch {} {}".format(condmove,self.curbranch))
    if self.curbranch is None:
      if len(self.branches)==0:
        br=Branch(condmove[0],condmove[1],condmove[2])
        self.branches.append(br)
        self.curbranch=self.branches[0]
        return True
      else:
        self.curbranch=self.branches[0]
    if self.curbranch.lastTaken is None:
      if self.curbranch.address==condmove[0]: #goto next branch/ wait for taking
        return True
      else:
        logger.warning("Trying to add branch for branch {} that was not triggered".format(self.curbranch.address))
        return False
    eo=self.curbranch.getExpectedOutput()
    if eo is not None: #already have output, got there or fail
      if eo[0]=="branch" and self.branches[eo[1]].address==condmove[0]:
        self.curbranch=self.branches[eo[1]]
        return True
      else:
        logger.warning("Failed following trace") 
        return False
    #new branch
    logger.info("new branch {} {} {}".format(self.index, self.curbranch.lastTaken,condmove[0]))
    br=Branch(condmove[0],condmove[1],condmove[2])
    self.curbranch.registerOutput(("branch",len(self.branches)))
    self.branches.append(br)
    self.curbranch=br
    if len(self.branches)>1024:
      logger.warning("Too many branches in one box")
      return False
    return True
  def registerIndexOutput(self,index):
    if self.curbranch is None:
      logger.warning("Trying to put output to empty branchbox")
      return False
    if self.curbranch.lastTaken is None:
      logger.warning("Trying to add branch for branch {} that was not triggered".format(self.curbranch.address))
      return False
    self.curbranch.registerOutput(("index",index))
    return True
  def reset(self):
    self.trace=None
    self.pathTaken=[]
    self.curbranch=None
    for br in self.branches:
      br.lastTaken=None
    if len(self.branches)>0:
     self.curbranch=self.branches[0]
  def loadTrace(self,trace):
    self.trace=trace
  def isTracing(self):
    return self.trace is not None
  def searchUntakenInTree(self, inindex):
    dbranch=self.branches[inindex]
    if dbranch.hasUntakenPaths(): return True
    if dbranch.trueIndex[0]=="branch":
      if self.searchUntakenInTree(dbranch.trueIndex[1]): return True
    if dbranch.falseIndex[0]=="branch":
      if self.searchUntakenInTree(dbranch.falseIndex[1]): return True
    return False
  def findNextUntakenStep(self):
    pth=self.curbranch.getNextUntaken()
    if pth is not None: return pth
    #recursive search...
    if self.curbranch.trueIndex[0]=="branch":
      if self.searchUntakenInTree(self.curbranch.trueIndex[1]): return True
    if self.curbranch.falseIndex[0]=="branch":
      if self.searchUntakenInTree(self.curbranch.falseIndex[1]): return False
    return None
  def takeUntakenOrTrace(self,emu):
    if len(self.branches)==0:
      logger.warning("Branch box not initialized")
      return
    if self.curbranch is None:
      self.curbranch=self.branches[0]
    if self.curbranch.address!=emu.getExecutionAddress():
      logger.warning("Branch box broken?")
      return
    if self.isTracing():
      if len(self.trace)>0:
        logger.info("Taking trace {}".format(self.trace[0]))
        self.curbranch.take(self.trace[0],emu)
        self.pathTaken.append(self.trace[0])
        out=self.curbranch.getExpectedOutput()
        self.trace=self.trace[1:]
        if out is None:
          logger.waring("Trace failed...")
          return
        #if out[0] is not "branch":
        #  self.curbranch=None
        #  return
        #self.curbranch=self.branches[out[1]]
      else:
       logger.warning("Trace bound violation")
       return
    else:
      pth=self.findNextUntakenStep()
      if pth is None:
        logger.warning("No untaken paths left for {}".format(self.index))
        return
      self.pathTaken.append(pth)
      logger.info("Taking {}".format(pth))
      self.curbranch.take(pth,emu)
        
     
class CPath(object):
  def __init__(self):
    self.path=[]
    self.ending=None #path can end in branch, return, baddata, basic loop or infinite loop (iloop)
    self.endJump=None
    self.multiend=False
  def contains(self,index):
    return index in self.path
  def addIndex(self,index):
    if not self.contains(index):
      self.path.append(index)
def estimateTableLen(table_addr,first_addr): # a rough estimate to be sure... the "switch guard" thing on top is usually lower
    cnt=0
    table=table_addr
    while  getInt(table)<0:
      naddr=table_addr.add(getInt(table))
      if naddr<first_addr or naddr>table_addr: break
      cnt+=1
      table=table.add(4)
    return cnt
def tryGetSwitchGuard(instr): #also mnemonic based, so fragile
  prev=instr.getPrevious()
  if prev is None: return -1
  prev=prev.getPrevious()
  nx=prev.getMnemonicString().lower()
  if nx == "cmp":
    objects=prev.getOpObjects(1)
    if len(objects)!=1: return -1
    try:
      return int(str(objects[0]),0)
    except:
      return -1
  return -1
#bVar2 = (**(code **)(*plVar5 + 0x20))(plVar5);
def hexornot(hon):
  try:
   return "{:X}".format(hon)
  except:
   return str(hon)
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


class BasicDataGraph(object):
  def __init__(self):
    self.registers={}
    self.variables={}
    self.inputs=set([])
        #logger.info(instr.getDefaultOperandRepresentation(0))
       #logger.info(instr.getDefaultOperandRepresentation(1))
  def maybeInput(self,inp):
    if inp.type=="register" or inp.type=="stackvar":
      if not inp.value in self.registers and not inp.value in self.variables:
        if not inp.value in self.inputs:
          self.inputs.add(inp.value)
  def getDeps(self,inp):
    if inp.type=="register":
      if inp.value in self.registers:
        return set(self.registers[inp.value])
    if inp.type=="stackvar":
      if inp.value in self.variables:
        return set(self.variables[inp.value])
    if inp.value in self.inputs:
      return set([inp.value])
    return set([])
  def assign(self,outp,inp):
    self.maybeInput(inp)
    ival=self.getDeps(inp)
    if outp.type=="register":
      self.registers[outp.value]=ival
    elif outp.type=="stackvar":
      self.variables[outp.value]=ival
    else:
      log.warning("Weird assign to {}".format(outp.type))
  def addDependency(self,recv,incoming):
    if recv.type=="register":
      if not recv.value in self.registers:
        self.registers[recv.value]=set()
      receiver=self.registers[recv.value]
    elif recv.type=="stackvar":
      if not recv.value in self.variables:
        self.variables[recv.value]=set()
      receiver=self.variables[recv.value]
    else:
      return # we don't care?
    for inp in incoming: #add direct ,leave propagation for later
      self.maybeInput(inp)
      ival=self.getDeps(inp)
      if inp.type=="register":
        receiver.update(ival)
      elif inp.type=="stackvar":
        receiver.update(ival)
      else:
       continue #consts, etc should not matter
  def scrambleRegisters(self): #we lose depedency over call
    for reg in self.registers:
      self.registers[reg]=set([])
  def add(self,instr):
    logger.info(instr)
    mn=instr.getMnemonicString().lower()
    if mn== "call":
      self.scrambleRegisters()
    elif mn=="mov" or "movzx" in mn: #assign
      output=Operand(instr,0)
      input=Operand(instr,1)
      self.assign(output,input)
    elif mn=="imul"or mn=="sub" or mn=="add" or mn=="and" or mn=="xor":
      no=c_instr.getNumOperands()
      output=Operand(instr,0)
      inputs=[Operand(instr,1)]
      if no==3:
       inputs.append(Operand(instr,2))
      self.addDependency(output,inputs)
    else:
      pass #maybe do not matter
  def getByMnem(self,mnem):
   root=set([])
   if mnem in self.variables:
    root=set(self.variables[mnem])
   rgs=currentProgram.getRegister(str(mnem))
   if rgs is not None:
     rgs=rgs.getBaseRegister()
     if str(rgs) in self.registers:
       root=self.registers[str(rgs)]
     else:
       root=set([])
     for r in rgs.getChildRegisters():
       if str(r) in self.registers:
         root.update(self.registers[str(r)])
   if mnem in self.registers:
    return set(self.registers[mnem])

   return root
  def linksTo(self,mnem):
   logger.info("mnem")
   logger.info(mnem)
   root=self.getByMnem(mnem)
   logger.info("added")
   logger.info(self.variables)
   logger.info(self.registers)
   logger.info(self.inputs)
   return root 
   
class mchain(object):
  def __init__(self,primary):
   self.mainRef=primary
   self.secref=set([])
  def addSecondary(self,mnem):
   self.secref.add(mnem)
  def string(self,emu):
   index=emu.readRegister(self.mainRef)
   ihash=0
   istr=""
   for scr in self.secref:
     reg=currentProgram.getRegister(str(scr))
     if reg is not None:
      ro=0
      ref=emu.readRegister(reg)
     else:
      ro=int(scr,0)
      ref=emu.readStackValue(ro,4,False)
     istr=istr+"_{:x}_{:x}|".format(ro,ref)
     ihash = (ref + (ihash << 6) + (ihash << 16) - ihash*ro)&0xffffffff
   return "0x{:x}_{}".format(index,istr)
  #readStackValue
import os
import json
#needs checksum detection! checksum has 3 stackvars: checksum, current addr and final addr
class ObfuscatedPath(object):
  def __init__(self):
    self.switchAddr=None # jmp RAX instruction/ switch that controls flow. should be first cbranch, usually
    self.jtableBreakpoint=None # movsxd instruction
    self.jtableRef=None
    self.jindexRef=None #register that contains jump index at jtableBreakpoint
    self.estimatedTableLen=-1
    self.paths=[]
    self.cpi=-1 #current path index
    self.branchboxes={}
    self.lastindex=-1
    self.loadedBox=None
    self.trace=None
    self.curFullPath=[]
    self.startpoint=state.getCurrentLocation()
    self.cur_fun=getFunctionContaining(self.startpoint.address)
    self.emu=None
    self.monitor=ConsoleTaskMonitor()
    self.loopAvoider=1000
    self.loopAvoid=self.loopAvoider
    self.mchl=1 #ok, memory chain does not really work XD Needs to check for hidden variables/ pathbox... 
    self.mch=None
    self.instructionBlock=[]
    self.maxflushes=10
    self.curflushes=0
    self.flushed=False
    self.saveregs= ["RIP", "RAX","RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "R15","rflags","R8","R9"]
    self.stackvars=set()
    self.collectedData={}
    self.entry="0x{}".format(self.cur_fun.getEntryPoint())
    if os.path.isfile(DATA_FILE):
     with open(DATA_FILE,"rb") as fl:
       dat=fl.read()
       if len(dat)>0:
         try:
          self.collectedData=json.loads(dat)
         except Exception as e:
          logger.warning("Error reading data file: {}".format(e))
          self.collectedData={}
    if not self.entry in self.collectedData :
      self.collectedData[self.entry]={"step":0}
      
  def initEmulator(self):
    if self.emu is not None:
      self.emu.dispose()
    self.emu=EmulatorHelper(currentProgram)
    mainFunctionEntryLong = int("0x{}".format(self.cur_fun.getEntryPoint()), 16)
    self.emu.writeRegister(self.emu.getPCRegister(), mainFunctionEntryLong)
    self.emu.writeRegister("RSP", 0x000000002FFF0000)
    self.emu.writeRegister("RBP", 0x000000002FFF0000)
  def indexInPaths(self, index):
    for pth in self.paths:
      if pth.contains(index): return True
    return False
  def loadBox(self):
    self.loadedBox=None
    si=self.mch.string(self.emu)
    if si in self.branchboxes:
        logger.info("Loaded box {}".format(si))
        self.loadedBox=self.branchboxes[si]
        self.loadedBox.reset()
  def findUntakenBranch(self):
    for bb in self.branchboxes:
      if self.branchboxes[bb].hasUntakenPaths():
        logger.info("Branch box at {} has untaken path, restarting".format(bb))
        return self.branchboxes[bb]
    return None
  def restart(self):
    self.initEmulator()
    self.loadedBox=None
    self.cpi=-1
    self.curFullPath=[]
    self.instructionBlock=[]
    self.flushed=True
  def run(self):
    for a in range(170000):
     if not self.process():
       bb=self.findUntakenBranch()
       if bb is None:
         logger.info("No untaken paths left, stopping")
         return
       self.trace=bb.pathToBox
       logger.info(bb.pathToBox)
       self.restart()
  def initNewPath(self,index):
    ind=len(self.paths)
    npath=CPath()
    npath.addIndex(index)
    self.paths.append(npath)
    self.cpi=ind
  def endPath(self,cause,jmp=None): #iloop, loop, branch, ret, baddata
    if self.cpi==-1:
      logger.warning("Trying to end path as {}  when not on path".format(cause))
      return
    logger.info("Ending path {} ({}) as {}".format(self.cpi,self.paths[self.cpi].path,cause))
    pth=self.paths[self.cpi]
    pth.ending=cause
    pth.endJump=jmp
    self.cpi=-1
  def runStraight(self,nl):
    for a in range(nl):
      executionAddress = self.emu.getExecutionAddress()  
      logger.info("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
      ein=getInstructionAt(executionAddress)
      if "{}".format(ein)=="CMP EAX,0x347":
        reg_value = self.emu.readRegister("EAX")
        logger.info("EAX: 0x{:x}".format(reg_value))
      if not self.step(): return
  def flush(self):
    if self.curflushes>=self.maxflushes: return
    self.trace=None
    self.branchboxes={}
    self.paths=[]
    self.restart()
    logger.info("Flushed branches, rebuilding, current secondary: {}".format(self.mch.secref))
    self.curflushes+=1
  def analyzeInstrBlock(self):
    if len(self.instructionBlock)<10: return False
    if self.curflushes>=self.maxflushes: raise NotImplementedError
    if self.flushed:
      self.flushed=False
      return False
    bdg=BasicDataGraph()
    for instr in self.instructionBlock:
      bdg.add(instr)
    affects=bdg.linksTo(self.jindexRef)
    logger.info(affects)
    prelen=len(self.mch.secref)
    for a in affects:
      if currentProgram.getRegister(str(a)) is not None: continue # avoid registers for now
      self.mch.addSecondary(a)
    if len(self.mch.secref)!=prelen:
      return True
    #self.curflushes+=1
    return False
  def save(self):
    with open(DATA_FILE,"wb") as fl:
       fl.write(json.dumps(self.collectedData).encode("utf-8"))
  def detectLongLoops(self):
    marks={}
    prev=None
    maxLoop=10
    window=[]
    cloop=None
    coffs=0
    clc=0
    cnt=0
    loopBreaks=[]
    loops=[]
    for ind in self.collectedData[self.entry]["basicChain"]:
      if cloop is not None:
        if ind != cloop[coffs]:
         #loop break
         logger.warning("Lbreak {} {} ".format(ind,cloop))
         loopBreaks.append(cnt-1)
         if clc>=5:
             loops.append((clc,cloop))
         cloop=None
         clc=0
         coffs=0
        else:
         coffs+=1
         if coffs>=len(cloop):
           clc+=1
           coffs=0
      else:
        if ind in window:
          cloop=window[window.index(ind):]
          while ind in cloop[1:]:
            l=cloop[1:]
            cloop=l[l.index(ind):]
          clc=0
          coffs=1
      window.append(ind)
      if len(window)>maxLoop:
           window=window[1:]
      cnt+=1
    logger.info("Detected loops: {}".format(loops))
    logger.info("Detected loop breaks: {}".format(loopBreaks))
    self.collectedData[self.entry]["basicLoops"]=loops
    self.collectedData[self.entry]["basicLoopBreaks"]=loopBreaks
  def getState(self):
    state={}
    for reg in self.saveregs:
      val=self.emu.readRegister(reg)
      state[reg]=val
    for v in self.stackvars:
      val=self.emu.readStackValue(int(v.value,16),v.length,False)
      state["{}_{}".format(v.value,v.length)]=val
    return state
  def writeState(self,state):
    for reg in self.saveregs:
      if reg in state and reg!="RIP":
       self.emu.writeRegister(reg,state[reg])
    for v in self.stackvars:
      ref="{}_{}".format(v.value,v.length)
      if ref in state:
        self.emu.writeStackValue(int(v.value,16),v.length,state[ref])
  def tryRun(self,nl):
    step=self.collectedData[self.entry]["step"]
    if step==0:
      while self.jtableBreakpoint is None:
        self.process() #replace with initCollect
      self.flush()
      self.collectedData[self.entry]["jtableBreakpoint"]="0x{}".format(self.jtableBreakpoint)
      self.collectedData[self.entry]["jindexRef"]=str(self.jindexRef)
      self.collectedData[self.entry]["estimatedTableLen"]=self.estimatedTableLen
      self.collectedData[self.entry]["stackvars"]=[]
      self.collectedData[self.entry]["callIndices"]=[]
      for sv in self.stackvars:
        self.collectedData[self.entry]["stackvars"].append([sv.type,sv.value,sv.length])
      self.collectedData[self.entry]["step"]=1
      step=1
      self.save()
    else:
      eaddr = self.emu.getExecutionAddress() 
      ein=getInstructionAt(eaddr)
      if self.jtableBreakpoint is None:
       self.jtableBreakpoint=getAddress(int(self.collectedData[self.entry]["jtableBreakpoint"],16))
       self.jindexRef=self.collectedData[self.entry]["jindexRef"]
       self.estimatedTableLen=self.collectedData[self.entry]["estimatedTableLen"]
       for sv in self.collectedData[self.entry]["stackvars"]:
         op=Operand(None,0)
         op.type=sv[0]
         op.value=sv[1]
         op.length=sv[2]
         self.stackvars.add(op)
    if step==1: #run till the end, marking indices
      self.collectedData[self.entry]["basicChain"]=[]
      while(True):
        executionAddress = self.emu.getExecutionAddress()
        ein=getInstructionAt(executionAddress)
        if executionAddress==self.jtableBreakpoint:
          #index=self.mch.string(self.emu)
          index=self.emu.readRegister(self.jindexRef)
          self.collectedData[self.entry]["basicChain"].append(index)
          logger.info("At index: {:X}".format(index))
          if index>self.estimatedTableLen:
            logger.info("Hit switch guard")
            break
        if isReturn(ein):
          logger.info("Got to return scessfully")
          break
        branch=getCondmoveInstruction(ein)
        if branch is not None:
          logger.info("Address: 0x{} ({})".format(executionAddress, ein))
        if isCallInstruction(ein):
          logger.info("Skipping call : 0x{} ({})".format(executionAddress, ein))
          self.collectedData[self.entry]["callIndices"].append(index)
          skip(self.emu)
        elif isCallOther(ein):
          logger.info("Skipping : 0x{} ({})".format(executionAddress, ein))
          skip(self.emu)
        else:
        #logger.info("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
          if not self.step(): break
      self.detectLongLoops()
      self.collectedData[self.entry]["step"]=2
      step=2
      self.save()
    else:
     pass
    self.restart()
    if step==2:
      self.detectLongLoops()
      lbr=self.collectedData[self.entry]["basicLoopBreaks"]
      if len(lbr)>0:
       cnt=0
       while(True):
        executionAddress = self.emu.getExecutionAddress()
        ein=getInstructionAt(executionAddress)
        if executionAddress==self.jtableBreakpoint:
          index=self.emu.readRegister(self.jindexRef)
          if cnt in lbr:
            logger.info("At loop break {:x}".format(index))
            state=self.getState()
            if not "breakStates" in self.entry:
             self.collectedData[self.entry]["breakStates"]={}
            self.collectedData[self.entry]["breakStates"][cnt]={}
            self.collectedData[self.entry]["breakStates"][cnt][index]=state
          if index>self.estimatedTableLen:
            logger.info("Hit switch guard")
            break
          cnt+=1
        if isReturn(ein):
          logger.info("Got to return scessfully")
          break
        if isCallInstruction(ein):
          logger.info("Skipping call : 0x{} ({})".format(executionAddress, ein))
          self.collectedData[self.entry]["callIndices"].append(index)
          skip(self.emu)
        elif isCallOther(ein):
          logger.info("Skipping : 0x{} ({})".format(executionAddress, ein))
          skip(self.emu)
        else:
          if not self.step(): break
      self.collectedData[self.entry]["step"]=3
      step=3
      self.save()
    if step==3: #need to track the indices, jump the loops and jigger the non-loop conditions
      self.restart()
  def process(self): #todo: needs to check for intersections... memory chain, maybe? Nope  XD
    eaddr = self.emu.getExecutionAddress() 
    ein=getInstructionAt(eaddr)
    if self.jtableBreakpoint is None: #initialization of jump table
       jt=getPotentialJtableAccess(ein)
       # try to find local variables... poorly XD
       if ein is not None:
        for nop in range(ein.getNumOperands()):
          op=Operand(ein,nop)
          if op.type=="stackvar":
           self.stackvars.add(op)
       if jt is not None:
         logger.info("Found assumed jump at 0x{}".format(eaddr))
         self.jtableBreakpoint=eaddr
         self.switchAddr=jt[2]
         self.jtableRef=jt[0]
         jtableAddr=getAddress(self.emu.readRegister(self.jtableRef))
         self.jindexRef=jt[1]
         self.mch=mchain(self.jindexRef)
         self.estimatedTableLen=estimateTableLen(jtableAddr,self.cur_fun.getEntryPoint())
         logger.info("Jump table length estimated to be {}".format(self.estimatedTableLen))
         sGuard=tryGetSwitchGuard(ein)
         if sGuard>0:
           logger.info("Replacing jump table length with switch guard of {}".format(sGuard))
           self.estimatedTableLen=sGuard
           self.jtableBreakpoint=ein.getPrevious().getAddress()
           lval = int("0x{}".format(self.jtableBreakpoint), 16)
           self.emu.writeRegister(self.emu.getPCRegister(), lval)
           logger.info("Moving breakpoint to switch guard at 0x{}".format(self.jtableBreakpoint))
         return self.process()
       return self.step()
    if eaddr==self.switchAddr: # at switch
      self.instructionBlock=[]
    else:
      self.instructionBlock.append(ein)
    if eaddr==self.jtableBreakpoint:
      if self.analyzeInstrBlock(): # see if there are any more hidden variables...
        self.flush()
        return True #to avoid second restart
      self.loopAvoid=self.loopAvoider #did not hit infinite loop on the way
      index=self.mch.string(self.emu)#self.emu.readRegister(self.jindexRef)
      activePath=None
      if self.cpi!=-1:
        activePath=self.paths[self.cpi]
      if self.loadedBox is not None:
        if self.trace is None and self.cpi>=0: #degenerate 1-step loop is possible... 
          self.endPath("branch",self.lastindex)
        self.loadedBox.registerIndexOutput(index)
        self.curFullPath[-1].append(self.loadedBox.pathTaken)
      if self.trace is None and self.indexInPaths(index):
        if self.lastindex==index: #degenerate
         npath=CPath()
         npath.ending="loop"
         npath.endJump=index
         self.paths.append(npath)
        else:
         if self.cpi!=-1:
           self.endPath("loop") # most loops end in branches? though not all 
         else:
           if activePath is not None:
             activePath.multiend=True
        logger.info("Found potential obfuscated loop to 0x{:x}".format(index))
        return False
      if self.trace is None:
        if self.cpi==-1:
          self.initNewPath(index) #self.mch.string()
        else:
          self.paths[self.cpi].addIndex(index)
      self.curFullPath.append([index])
      logger.info("At index {}".format(index))
      self.lastindex=index
      self.loadBox()
      if self.trace is not None:
        tpt=self.trace[0]
        self.trace=self.trace[1:]
        if len(self.trace)==0:
           self.trace=None
        if tpt[0]!=index:
          logger.warning("Trace error, index mismatch!")
          return False
        if len(tpt)>1:
          if self.loadedBox is None:
            logger.warning("Trace error, should be branch box here!")
            return False
          self.loadedBox.loadTrace(tpt[1])
      if self.emu.readRegister(self.jindexRef)>self.estimatedTableLen:
        logger.info("Hit switch guard, retracing")
        self.endPath("iloop")
        #self.restart()
        return False
    branch=getCondmoveInstruction(ein)
    if branch is not None:
      if self.loadedBox is None:
        bbox=BranchBox(self.lastindex)
        bbox.pathToBox=[list(k) for k in self.curFullPath] #deep copy
        self.branchboxes[self.lastindex]=bbox
        self.loadedBox=bbox
      self.loadedBox.registerBranch(branch)
      self.loadedBox.takeUntakenOrTrace(self.emu)
      return True
    if isCallInstruction(ein):
      logger.info("Skipping call : 0x{} ({})".format(eaddr, ein))
      skip(self.emu)
      return True
    self.loopAvoid-=1
    if self.loopAvoid<0:
      self.endPath("iloop")
      return False
    if isReturn(ein):
      if self.cpi!=-1:
        self.endPath("return")
      return False
    return self.step()
  def step(self):
    success = self.emu.step(self.monitor)
    if (success == False):
       lastError = self.emu.getLastError()
       logger.error("Emulation Error: '{}'".format(lastError))
       if self.cpi!=-1:
         self.endPath("baddata")
    return success
    
location=state.getCurrentLocation()
print(location.address)
c_instr=getInstructionAt(location.address)
print(c_instr)
print(c_instr.getNumOperands())
print(type(c_instr.getOpObjects(0)[0]))
print(c_instr.getOpObjects(1))
print(listing.getInstructionBefore(c_instr.address))
print(c_instr.getOperandType(0))

print("{:x}".format(c_instr.getOperandType(1)))
print("{:x}".format(c_instr.getOperandType(2)))

cur_fun=getFunctionContaining(location.address)
print(cur_fun)

print(currentProgram.getRegister("ECX"))
print(currentProgram.getRegister("EdCX"))
print(c_instr.getDefaultOperandRepresentation(1))
#emuHelper = EmulatorHelper(currentProgram)
mainFunctionEntryLong = int("0x{}".format(cur_fun.getEntryPoint()), 16)
#emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)
registers = getProgramRegisterList(currentProgram)
reg_filter = [
        "RIP", "RAX"]#, "RBX", "RCX", "RDX", "RSI", "RDI", 
       # "RSP", "RBP", "rflags"

op=ObfuscatedPath()
op.initEmulator()
op.tryRun(50000000)
#op.restart()
#op.runStraight(5000)
op.emu.dispose()

