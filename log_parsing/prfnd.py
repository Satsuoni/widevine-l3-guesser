# use on the appropriate log file produced by ghidra
import sys
fl=sys.argv[1]
def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
    if (m == 1):
        return 0
    while (a > 1):
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if (x < 0):
        x = x + m0
    return x
n=0xBCA83D793F493C49DF558612E74C773198AB4901F20369BFAF1598D71E362EF13AB9BE3B4D4D73C63378542D23BEBA56AD4D589C1E7F151E25CF6F7A38F8FF1FF491D5D2DFC971617B6D9559406E3A5127B2AEBDDEA965E0DFCF4C50AE241CAF9E87BFE33B0DB619B5C395E3986E310A3278F990B4139A421AF74B3E4E1548250DEC8F1755B038E61069E2547983ED93878549B4A9F5FAA1BEF72A75A9929FA7240FB1E46B9587170EF993C29C35F1F145E55BFEC0DE85D2B9409D6599B1C348BF76DD441ABD53033475E3267F91647C2584D974D3AD7B8C0C33711556D6C2CF23BF7905B17A68C622A0580A623C1AF9F446294D5F2DE50721D85EB5F49B7013
rt=0x79bad423a3b14693488f32a3f32ca9cf96dbdfc5b45c7d4bba04af8958f008e3b7468b33f0f868eccc0b5b0fac5c60d131c2491b43dda75af695cfc303086204cb656f24b02024adef05c5e3be2f4918b67f7c75d3b9150b78ba70f4785515bd64e2905517559033e69a4a36501604c371a37137f56d64444b269538b87152169bf581d560bab993e4a6010f39f41fc97396f57eaecef874a469d5159ab5a71f6c9c5e1e4e7e5de2a7436604f47c695572b7b8916116044ba223c95eccaad9c3747dcdc56e966b1978a17282d9911d9bf314f1ef52971d4c4f59c1fcde5c4deeeb8ce02816aa24b79091d81e70c11c3f12dafad70b74eee3aa4a902a2d76b2bc
r=(1<<2048)
ri=modInverse(r,n)
rii=modInverse(ri,n)

accs=["Collected as HasMulAdd ,a : ",
"Collected as SubN ,a : ",
"Collected as Plus ,b : " ,
"Collected as Plum? ,b : ",
"Collected as Plum res ,b : ",
"Collected as Plus ,a : ",
"Collected as YetAnother ,a : ",
"Collected as MbSubtr ,a : ",
"Collected as Upper ,a : ",
 "Collected as MbSubtr ,b : ",
 "Grabbed "
 ]
priors=[]
mults={}
pluses={}
minuses={}
sqms={}
sqms2={}
relations={}

def checkPriorRelation(nm):
  global priors
  if nm in priors: return
  rel=False
  if nm in mults:
    relations[nm]=["mul",mults[nm]]
    del mults[nm]
    rel=True
  if nm in pluses and not rel:
    print("Sum")
    relations[nm]=["sum",pluses[nm]]
    del pluses[nm]
    rel=True
  if nm in minuses and not rel:
    print("Neg")
    relations[nm]=["neg",minuses[nm]]
    del minuses[nm]
    rel=True
  if rel is False:
      if nm in sqms:
        relations[nm]=["sqm",sqms[nm]]
  if rel is False:
     if nm in sqms2:
        print("Squam2")
        relations[nm]=["sqm2",sqms2[nm]]
  priors.append(nm)
  for k in range(len(priors)):
     p=priors[k]
     mi=(p*nm*ri)%n
     sqm=(p*mi*ri)%n
     sqm2=(nm*mi*ri)%n
     mp=(p+nm)%n
     mn=(p-nm+n)%n
     mn2=(nm-p+n)%n
     if nm<0: mn+=n
     if not mi in mults:
       mults[mi]=[k,len(priors)-1]
     if not mp in pluses:
       pluses[mp]=[k,len(priors)-1]
     if not mn in minuses:
       minuses[mn]=[k,len(priors)-1]
     if not mn2 in minuses:
       minuses[mn2]=[len(priors)-1,k]
     
lnm=0 

def save():
    import json
    st=json.dumps({"priors":priors, "relations":relations})
    fl=open("exp_values.json","w")
    fl.write(st)
    fl.close()
cnt=0
prev=None
with open(fl,"r",encoding="utf-8") as fl:
  for ln in fl:
    for acc in accs:
      if acc in ln:
       if "Grabbed " in ln:
        nm=int(ln.split(":")[1].strip(),16)%n
       else:
        nm=int(ln[len(acc):],16)%n
       lnm=nm
       if nm in priors:
        print("Prior")
       else:
        pass
       checkPriorRelation(nm)
       prev=nm
       cnt=cnt+1
       if cnt>100:
        cnt=0
        save()
       break
save()
