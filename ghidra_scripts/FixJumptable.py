#Simple jump table fixing. Select LEA instruction and JMP RAX (branchcond) instruction and run. Mostly copied from SwitchOverride.java. Does not always fix table correctly.
#@author Satsuoni
#@category Deobfuscation
#@keybinding 
#@menupath 
#@toolbar 

from binascii import hexlify
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import *
from ghidra.program.model.pcode import JumpTable
from java.util import LinkedList, Arrays, ArrayList
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    
def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers
    
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
listing = currentProgram.getListing()

print(name)
def getPossibleConstAddressFromInstruction(instr):
  raw_pcode = instr.getPcode()
  for code in raw_pcode:
    if code.getOpcode()==PcodeOp.COPY:
      inp=code.getInputs()[0]
      print(inp)
      if inp.size==8 and inp.isConstant():
       return getAddress(inp.getOffset())
  return None
       #return toAddr(inp.)
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
    
def tryGetSwitchGuard(instr): #also mnemonic based, so fragile. May not work, did not check in this script
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
  
def fixSwitch():
 selection=state.getCurrentSelection()
 table_addr=None
 first_addr=None
 jumpinstr=None
 jumpaddr=None
 if selection is not None:
  for item in selection:
    print(item)
    instr=getInstructionAt(item.getMinAddress())
    if first_addr is None or item.getMinAddress() < first_addr:
      first_addr=item.getMinAddress()
    if table_addr is None: 
     table_addr=getPossibleConstAddressFromInstruction(instr)
    if isComputedBranchInstruction(instr):
      jumpinstr=instr
      jumpaddr=item.getMinAddress()
 if table_addr is None:
   print("could not find table, should be in selection")
   return
 if jumpinstr is None:
   print("could not find jump point, should be in selection")
   return 
 table=table_addr
 cnt=0
 addr_list=[]
 while  getInt(table)<0:
  naddr=table_addr.add(getInt(table))
  if naddr<first_addr or naddr>table_addr: break
  addr_list.append(naddr)
  cnt+=1
  table=table.add(4)
 print("Estimated table length: {}".format(len(addr_list)))
 sGuard=tryGetSwitchGuard(jumpinstr)
 if sGuard>0:
   print("Switch guard found: {}".format(sguard))
   if sguard<len(addr_list):
     addr_list=addr_list[:sguard]
 if len(addr_list)==0:
   print ("Empty table?")
   return
 function = getFunctionContaining(jumpaddr)
 monitor = ConsoleTaskMonitor()
 for addr in addr_list:
   discmd = DisassembleCommand(addr, None, True)
   discmd.applyTo(currentProgram,monitor)
   jumpinstr.addOperandReference(0, addr, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED)
 jumpTab = JumpTable(jumpaddr,ArrayList(addr_list),True)
 #jumpTab.writeOverride(function)
 CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor)
fixSwitch()
