# run this with json file from previous step
import sys
import json
def modInverse(a, m):
    m0=m
    y=0
    x=1
    if (m == 1):
        return 0
    while (a > 1):
        q=a // m
        t=m
        m=a % m
        a=t
        t=y
        y= x - q * y
        x= t
    if (x < 0):
        x= x + m0
    return x
fl=sys.argv[1]
with open(fl,"r") as f:
  data=json.loads(f.read())
priors=data["priors"]
trees={}


n=0xBCA83D793F493C49DF558612E74C773198AB4901F20369BFAF1598D71E362EF13AB9BE3B4D4D73C63378542D23BEBA56AD4D589C1E7F151E25CF6F7A38F8FF1FF491D5D2DFC971617B6D9559406E3A5127B2AEBDDEA965E0DFCF4C50AE241CAF9E87BFE33B0DB619B5C395E3986E310A3278F990B4139A421AF74B3E4E1548250DEC8F1755B038E61069E2547983ED93878549B4A9F5FAA1BEF72A75A9929FA7240FB1E46B9587170EF993C29C35F1F145E55BFEC0DE85D2B9409D6599B1C348BF76DD441ABD53033475E3267F91647C2584D974D3AD7B8C0C33711556D6C2CF23BF7905B17A68C622A0580A623C1AF9F446294D5F2DE50721D85EB5F49B7013
r=(1<<2048)
ri=modInverse(r,n)
rii=modInverse(ri,n)
endpoint=priors[-1]
stp=pow(endpoint,65537,n)
donotexpand=[0] #,25,61,80,98,216
droot=5

class rootNode(object): #for single root with additions
  def __init__(self):
    self.snodes=[[droot,1]]
class expNode(object):
  def __init__(self):
    self.numconst=1
    self.subnodes={}
  def getVal(self):
    vl=self.numconst
    for sn in self.subnodes:
      if sn>=0:
       k=pow(priors[sn],self.subnodes[sn],n)%n
       vl=vl*k%n
    return vl%n
  def asConst(self, cnst):
    self.numconst=cnst
    self.subnodes={}
    return self
  def asNode(self, nd):
    self.numconst=1
    self.subnodes={nd:1}
    return self
  def asCopy(self,other):
    self.numconst=other.numconst
    self.subnodes={}
    for nd in other.subnodes:
      self.subnodes[nd]=other.subnodes[nd]
    return self
  def canAdd(self,other):
    if len(self.subnodes)!=len(other.subnodes): return False
    for sn in self.subnodes:
      if not sn in other.subnodes: return False
      if self.subnodes[sn]!=other.subnodes[sn]: return False
    return True
  def add(self,other):
    ret=expNode()
    ret.numconst=(self.numconst+other.numconst)%n
    ret.subnodes=self.subnodes.copy()
    return ret
  def convertToConst(self,num,val):
    if not num in self.subnodes: return
    pwr=pow(val,self.subnodes[num],n)*pow(ri,self.subnodes[num]-1,n)%n
    self.numconst=(self.numconst*pwr)%n
    del self.subnodes[num]
  def __repr__(self):
    return "{}".format(self.subnodes)
  def mul(self,other):
    ret=expNode()
    ret.numconst=self.numconst*other.numconst*ri%n
    st=set(self.subnodes.keys())|set(other.subnodes.keys())
    for vl in st:
      a1=self.subnodes.get(vl,0)
      a2=other.subnodes.get(vl,0)
      if vl>=0:
       ret.subnodes[vl]=a1+a2
      else:
       if a1+a2<=1:
        ret.subnodes[vl]=a1+a2
       else:
        ret.numconst=0
    return ret
def reduceList(lst):
  ret=[]
  lc=list(lst)
  while len(lc)>0:
    cr=lc.pop()
    rl=[]
    for pt in lc:
     if cr.canAdd(pt):
      cr=cr.add(pt)
     else:
      rl.append(pt)
    lc=rl
    if cr.numconst>0:
      ret.append(cr)
  return ret
    
def mulList(ls1,ls2):
  retl=[]
  for a in ls1:
    for b in ls2:
      retl.append(a.mul(b))
  if len(ls1)>0 and len(ls2)>0:
    return reduceList(retl)
  else:
    return retl
  
class expVariable(object):
  def __init__(self,num,nodes,priors,rel):
   self.num=num
   self.nodes=[]
   if rel is None:
     self.nodes=[expNode().asConst(priors[num])]
     return
   if rel=="root":
     self.nodes=[expNode().asNode(num)]
     return
   if rel=="ism":
     self.nodes=[expNode().asNode(-1),expNode().asNode(-2)]
     return
   nd1=nodes[rel[1][0]]
   nd2=nodes[rel[1][1]]
   if rel[0]=="mul":
     self.nodes=mulList(nd1.nodes,nd2.nodes)
   elif rel[0]=="sum":
     ndlist=[expNode().asCopy(n) for n in nd1.nodes]+[expNode().asCopy(n) for n in nd2.nodes]
     self.nodes=reduceList(ndlist)
   elif rel[0]=="neg":
     cnst=expNode().asConst((n-1)*r%n)
     ndlist=[expNode().asCopy(n) for n in nd1.nodes]+[n.mul(cnst) for n in nd2.nodes]
     self.nodes=reduceList(ndlist)
  def spow(self):
    ndlist=[kn.mul(expNode().asConst(r*r%n)) for kn in self.nodes]
    ndlist2=mulList(ndlist,ndlist) # ^2
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist2=mulList(ndlist2,ndlist2)
    ndlist=mulList(ndlist,ndlist2)
    lst=[kn.mul(expNode().asConst(1)) for kn in ndlist]
    print(lst)
    print("{:x}".format(lst[0].numconst))
    print("{:x}".format(lst[1].numconst))
    ret=expVariable(-2,nodes,priors,None)
    ret.nodes=lst
    return ret
     
     
for p in priors:
 print("{}: {:x}".format(priors.index(p),p))
 print("> {:x}".format(p*ri%n))
 print("> {:x}".format(modInverse(p*ri%n,n)))
if "relations" in data:
 rels={}
 for et in data["relations"]:
   rels[int(et)]=data["relations"][et]
 lst=[priors.index(endpoint)]
 awl=set([])
 while len(lst)>0:
  kp=lst[0]
  lst=lst[1:]
  if kp in awl: continue
  awl.add(kp)
  kpp=priors[kp]
  if kpp in rels:
   for k in rels[kpp][1]:
     if not k in awl:
      lst.append(k)
      
nodes={}
disms=[]
for k in range(0,len(priors),1):
  ld=expVariable(k,nodes,priors,rels.get(priors[k],None))
  if len (ld.nodes)>100 and len(disms)==0:
       donotexpand.append(k)
       print("Adding as node {}".format(k))
  if k in disms:
   nd=expVariable(k,nodes,priors,"ism")
   nd.nodes.append(expNode().asConst(priors[k]))
   #nd=expVariable(k,nodes,priors,None)
  elif k in donotexpand:
    nd=expVariable(k,nodes,priors,"root")
  else:
    #print(rels.get(priors[k],None))
    nd=expVariable(k,nodes,priors,rels.get(priors[k],None))
  nodes[k]=nd
  print("{}: {}".format(k,rels.get(priors[k],None)))
  print("{}: {} -> {}".format(k,nd.nodes,len(nd.nodes)))
  #if k==len(priors)-1:
  for nod in nd.nodes:
     print("{:x}".format(nod.numconst))
  if len(nd.nodes)==1:
     print("{:x}".format(nd.nodes[0].getVal()))
  if False:#k==len(priors)-1:
     ec=pow(12,65537,n)
     a=priors[25]
     for s in range(29,4385,1):
         nd=nodes[s]
         if len(nd.nodes)!=2: continue
         print(s)
         if len(nd.nodes[0].subnodes)==0:
           res=nd.nodes[0].numconst
           der=nd.nodes[1].numconst
         else:
           res=nd.nodes[1].numconst
           der=nd.nodes[0].numconst    
         print("Res: {:x}".format(res))
         print("Der: {:x}".format(der))  
         print("Aaa: {:x}".format(a))       
         dk=der*a*modInverse(res,n)%n
         #dk=dk*ri%n
         print("Hmm: {:x}".format(dk))
         print(pow(ec,dk,n))
print("Ending")
sys.exit()
nd=nodes[len(priors)-1]
print("{:x}".format(nd.nodes[0].numconst))
print("{:x}".format(nd.nodes[1].numconst))
print("{:x}".format(nd.nodes[3].numconst))
dfx2=nd.nodes[3].numconst
rnd=nd.spow()
print("rn {:x}".format(rnd.nodes[0].numconst))
print("rn {:x}".format(rnd.nodes[1].numconst))
dx2=rnd.nodes[3].numconst
kn=3142033101700003260678755863863267700134374886049156296238778043258513471417667391237505300342672722921505586813412391537592394712287451780540489111338082979901966887630936873112829448279475520471433931949082770983040743133849146064289054900225131501940560027662491217132619227565578893295128589581903273904124801461070363532834633728769178636552784294153467969250254358604276515140477045217505629092433114246051368410587618590542410950189868285511930901887132942539241081579465767831350539339965000260768249119651905050152151634478714116343168832447694793716937575319879226685046081583200335708696821445923072794535
print("rx {:x}".format(kn*65537%n))
print("rrn {:x}".format(rnd.nodes[3].numconst))
x=rnd.nodes[0].numconst
fx=nd.nodes[0].numconst
dfa=nd.nodes[1].numconst*modInverse(rnd.nodes[1].numconst,n)%n
print("{:x}".format(dfa))
dfq=dfa*x*modInverse(fx,n)%n
print("{:x}".format(dfq))
print("{:x}".format(pow(x,dfq,n)))
   #nd.nodes[0].numconst
#res=nd.nodes[0].numconst*2
#der=nd.nodes[1].numconst*2
#dk=der*pow(res,65537,n)*modInverse(res,n)%n
#kn=3142033101700003260678755863863267700134374886049156296238778043258513471417667391237505300342672722921505586813412391537592394712287451780540489111338082979901966887630936873112829448279475520471433931949082770983040743133849146064289054900225131501940560027662491217132619227565578893295128589581903273904124801461070363532834633728769178636552784294153467969250254358604276515140477045217505629092433114246051368410587618590542410950189868285511930901887132942539241081579465767831350539339965000260768249119651905050152151634478714116343168832447694793716937575319879226685046081583200335708696821445923072794535
#print("kn: {:x}".format(kn))
#print("{:x}".format(dk))
#print("{:x}".format(priors[3]))
#print("{:x}".format(pow(res,65537,n)))
#print(res)
for k in range(len(priors)):
  print("{}: {}".format(k,rels.get(priors[k],None)))
sys.exit()
