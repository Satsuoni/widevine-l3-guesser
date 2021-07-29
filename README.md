# Trying to extract Widewine key: A journey to FaIlUrE

## Notes

- This work is based (obviously) on the [widevine-l3-decryptor extension](https://github.com/cryptonek/widevine-l3-decryptor). Many parts are the same, parts of Readme are a verbatim copy, etc.
- I have no working knowledge of Chrome extension structure.
- Some parts of code are copied from RFC documents, wikipedia, etc. *shrug*
- Tldr: The result seems to work, but relies on code lifting into wasm module and lots of brute-forcing, resulting in about 15-minute wait for a single RSA decryption.
- I am too lazy to improve on this.

## Introduction

[Widevine](https://www.widevine.com/solutions/widevine-drm) is a Google-owned DRM system that's in use by many popular streaming services (Netflix, Spotify, etc.) to prevent media content from being downloaded.

But Widevine's least secure security level, L3, as used in most browsers and PCs, is implemented 100% in software (i.e no hardware TEEs), thereby making it reversible and bypassable.

This Chrome extension demonstrates how it's possible to bypass Widevine DRM by hijacking calls to the browser's [Encrypted Media Extensions (EME)](https://www.html5rocks.com/en/tutorials/eme/basics) and (very slowly) decrypting all Widevine content keys transferred - effectively turning it into a clearkey DRM.

## Usage
To see this concept in action, just load the extension in Developer Mode and browse to any website that plays Widevine-protected content, such as https://bitmovin.com/demos/drm _[Update: link got broken?]_.
First, extension will try to brute-force input encoding for the code-lifted part, dumping progess to console. Then, assuming it succeeds, keys will be logged in plaintext to the javascript console.

e.g:

```
WidevineDecryptor: Found key: 100b6c20940f779a4589152b57d2dacb (KID=eb676abbcb345e96bbcf616630f1a3da)
```

Decrypting the media itself is then just a matter of using a tool that can decrypt MPEG-CENC streams, like `ffmpeg`. 

e.g:

```
ffmpeg -decryption_key 100b6c20940f779a4589152b57d2dacb -i encrypted_media.mp4 -codec copy decrypted_media.mp4
```
**NOTE**: The extension currently supports the Windows platform only.

## How I got here

### Starting point

It is my honest opinion that DRM is a malignant tumor growing upon various forms of media, and that people that either implement or enforce implementation are morally repugnant and do no good to society. With that in mind, I was sad to learn in May 2021 that the original extension would soon be rendered obsolete. I found myself with some free time on my hands, and so I decided to try and replicate original key extraction. Unfortunately, there was not much data pertaining to what process the original's authors used, and even some confusion as to [who was the one who performed extraction](https://github.com/tomer8007/widevine-l3-decryptor/issues/14). Nevertheless, I decided to give it a go, and hopefully boost my flagging self-confidence a little. I did not succeed in either of those tasks, but I managed to write a barely-functioning decryptor, and decided to document the steps I followed, in case they are of use to somebody else. 

### Reverse enginering and emulating

In order to deal with executable, I decided to use [Ghidra](https://github.com/NationalSecurityAgency/ghidra), despite its association with NSA, mostly because it is free and has most features that I wanted. I also wrote a simple snippet to be able to debug dll.

```
lib = LoadLibrary(L"widevinecdm_new.dll");
if (lib != NULL)
{
    InitializeCdmModule init_mod = (InitializeCdmModule)GetProcAddress(lib, "InitializeCdmModule_4");
    CreateCdmInstance create = (CreateCdmInstance)GetProcAddress(lib, "CreateCdmInstance");
    GetCdmVersion getver=(GetCdmVersion)GetProcAddress(lib, "GetCdmVersion");
    printf("%d\n", (ulonglong)init_mod);
    init_mod();
    printf("%d %s\n", (ulonglong)create,getver());
    getchar();
    printf("Creating\n");
    std::string keys = "com.widevine.alpha";
    std::string clearkeys = "org.w3.clearkey";
    ContentDecryptionModule_10* cdm =(ContentDecryptionModule_10 *) create(10, keys.c_str(), keys.length(), GetDummyHost, (void*) msg);
    printf("Created? %d \n", (ulonglong)cdm);
    unsigned int pid = 10;
    const char* sid = "Sessid";
    //pssh box?
    byte initdata[92]= { 0, 0, 0, 91, 112, 115, 115, 104, 0, 0,
                         0, 0, 237, 239, 139, 169, 121, 214, 74,
                  206, 163, 200, 39, 220, 213, 29, 33, 237, 0, 0,
                0, 59,  8,  1, 18, 16, 235, 103, 106, 187, 203, 52,
                94, 150, 187, 207, 97, 102, 48, 241, 163, 218, 26, 13,
               119, 105, 100, 101, 118, 105, 110, 101, 95, 116, 101,
              115, 116, 34, 16, 102, 107,106, 51, 108, 106, 97, 83,
              100, 102, 97, 108, 107, 114, 51, 106, 42, 2, 72, 68,50, 0};
    gcdm=cdm;
    printf("First compare: %d\n",(int)((byte *)gcdm)[0x92]);
    cdm->Initialize(true, false, false);
    printf("Sc compare: %d\n", (int)((byte*)gcdm)[0x92]);
    getchar();
    cdm->CreateSessionAndGenerateRequest(pid,SessionType::kTemporary,InitDataType::kCenc,initdata,91);
}
```

All structures in the above snippet are copied from Chromium eme sources, for example [here](https://chromium.googlesource.com/chromium/src/media/+/refs/heads/main/cdm/cdm_wrapper.h). 

First things first, I tried running the  resulting program, producing proper signature as an (intermediate) result. Trying to trace it in debugger, however, caused problems. At first, it just crashed with access violation. After modifying *BeingDebugged* field in PEB, it instead went into infinite loop. 

Looking at the decompiled code revealed a large amount of strange switch statements in most API functions. It looked somewhat like the following (from Ghidra decompiler):

```
while(true)
  {
  uVar5 = (longlong)puVar3 + (longlong)(int)puVar3[uVar5 & 0xffffffff];
  switch(uVar5) {
  case 0x1800f489e:
    uVar5 = 5;
    goto LAB_1800f488e;
  case 0x1800f48ad:
    local_20 = local_2c + 0x47b0e7d4;
    uVar5 = 3;
    goto LAB_1800f488e;
  case 0x1800f48c1:
    uVar5 = 0x17;
    goto LAB_1800f488e;
  case 0x1800f48c8:
    local_28 = local_20 - local_2c;
    bVar1 = (int)(uint)local_21 < (int)(local_28 + 0xb84f182c);
    unaff_RSI = (undefined *)(ulonglong)bVar1;
    uVar5 = (ulonglong)((uint)bVar1 * 5 + 2);
    goto LAB_1800f488e;
  case 0x1800f48f4:
    local_28 = local_2c + 0xd689ea6;
    uVar5 = 0x16;
    goto LAB_1800f488e;
  case 0x1800f4908:
    uVar5 = 0x19;
    goto LAB_1800f488e;
  case 0x1800f491a:
    local_2c = local_2c & local_28;
    uVar5 = 1;
    goto LAB_1800f488e;
  case 0x1800f492c:
    if (true) {
      *(undefined *)&param_1->_vtable = *unaff_RSI;
      unaff_RSI[1] = unaff_RSI[1] - (char)(uVar5 >> 8);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
...
```

After several days of investigation, it became obvious that that is a form of code obfuscation, breaking down code flow into small segments and arranging them in switch statement in order defined by a primitive PRNG. PRNG can be controlled to execute if/else statements and loops. The *halt_baddata* portion causes access violation crash when reached. Any jump table index outside bounds leads to *while(true)* executing indefinitely. Since switch is driven by PRNG, decompiler cannot seem to find limits of jump tables, resulting in invalid switch statements or mangled decompilation. I tried to ameliorate that by [fixing jump tables](ghidra_scripts/FixJumptable.py), but results were not encouraging. I then tried to [follow the instruction flow](ghidra_scripts/Deobfuscatorr.py) by using Ghidra Emulator API. AFter a lot of experimentation, I drew the following conclusions:

- Many of the switch cases are almost-duplicates, and some are either never reached or only reached in case of failed check, craching program or sending it into infinite loop. 
- The anti-debugging code is hidden within the switch statements.
- Most of anti-debugging code seems to be similar to what is decribed [here](https://anti-debug.checkpoint.com/techniques/misc.html). The list of the debugger windows names is exactly the same, which is amusing (and outdated).  
- Some functions actually use memory checksums **as PRNG seeds** which makes guessing where it would go after impossible without knowing the checksum. And how many iterations it took to calculate it. And results of various checks in the middle. Etc...
- None of the anti-debugger tricks are activated by emulation, but emulation is literally hundreds, if not thousands of times slower than direct CPU execution, so that checksum calculation can take several hours (depending on log verbosity).
- Emulating just one function does not help much, since flow might depend on input parameters :( .

After that, I tried to reverse Protobuf encoding/decoding functions found in the code. While I did manage to find some of them (using *getchar* as a convenient breakpoint to attach debugger), they did not match Protobuf functions in the original repository, leading me to believe that the source file was changed. For example, SignedMessage now has more than 9 fields, rather than original 5. Luckily, protocol seems backward compatible enough, so the necessary signatures/keys can still be extracted. To parse protobuf messages, I used either original extension or this [convenient website](https://protogen.marcgravell.com/decode). 

In any case, that investigation did not seem to lead anywhere, and in the end (after several weeks and lots of cursing), I decided to emulate the whole program in Ghidra. To that end, I developed a simple [script](ghidra_scripts/Longsusrunner.py) that emulated system and host calls made by DLL. Necessary system calls were extracted by just running emulation until it came to the code it could not execute and replacing that with  python function. As an aside, script executes one instruction at a time, so it is slower than using Ghidra breakpoints, but easier for me to manage. Manipulating it allowed me to dump logs of program flow and memory contents, as well as save and restore simulator state. Eventually, I managed to reach point where emulator formed a valid signature and called into fake host code with it. It took several days, though, with the longest part being something that seemed to be jump table and calculation table generation. After that, it was just a matter of tracing signature back to generation function. 

![Probable signature generation function](images/screen1.png?raw=true)


### Extracting part of the exponent

After staring at the wall of poorly decompiled code for a while, I realized that parts of it implement a simple Bignum multiplicaion algorithms, but instead of using linear arrays, they used arrays permuted by PRNG-like functions, so every arithmetic operation was preceded by permutation generator looking kind of like this:

```
 uint * PFUN_180119595(uint *param_1,uint *out,uint length,int param_4)

{
  byte *pbVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  bool bVar7;
  
  uVar6 = (ulonglong)(length * 4);
  if (*(char *)((longlong)out + uVar6) != '\x02') {
    do {
      pbVar1 = (byte *)((longlong)out + uVar6);
      bVar7 = *pbVar1 == 0;
      *pbVar1 = *pbVar1 ^ bVar7 * (*pbVar1 ^ 1);
    } while ((byte)(!bVar7 * *pbVar1) == '\x01');
    if (bVar7) {
      if (length != 0) {
        uVar5 = param_4 * 0xe286515;
        uVar3 = 0;
        do {
          uVar2 = param_1[uVar3];
          uVar4 = uVar2 ^ uVar5;
          out[uVar3] = uVar4;
          uVar5 = uVar5 + uVar2 * uVar4;
          uVar3 = uVar3 + 1;
        } while (length != uVar3);
      }
      *(undefined *)((longlong)out + uVar6) = 2;
    }
  }
  return out;
}
```

Same function was used most of the time, but with different offsets and initial arrays, resulting in a variety of permutations. Regardless, I was able to roughly identify montgomery multiplications, subtractions and additions performed on 256-byte arrays (implying the use of 2048 bit keys). One of the most important factors was the use of "ADC" assemler command, mostly restricted to two areas of the code, which I tentatively identified as "signature generation" and "session key decryption". I concentrated on the former, since I could access and verify the output. Which did however raise the question about what kind of input the function took. More about that later. 

Of course, sick, sadisitic minds behind the obfuscation did not use a straightforward exponentiation algorithms. As described in Google patent [US20160328543A1](https://patentimages.storage.googleapis.com/0c/f3/c0/08ce4394385810/US20160328543A1.pdf), they multiply input by constant and output by reversing constant, use permutation function to confuse memory layouts, and seem to use "split variables" at times, though not often in this case. In any case, resulting exponentiation function also has some additions which cancel each other in the end. 

In order to extract the exponent from the code, I first logged most of the inputs and outputs of the functions that seemed to operate on bignum, unscrambling the permutation using the already generated tables in memory. Then, I used [python script](log_parsing/prfnd.py) to guess the operations performed on the numbers, and a [separate script](log_parsing/prfold.py) to map those operations into a tree. The second script went through several iterations as I tried various things, including adding [dual number](https://en.wikipedia.org/wiki/Dual_number) support in order to extract exponent from the result's derivative. Ultimately, I settled on simple single-variable tracing. Finding a route that did not lead to exponential explosion in number of polynomial powers was somewhat of a challenge, but eventually (after,once again, a week or two of work :| ) I succeded in extracting an exponent and multiplicative constant:

```
Integer sec_pwr("3551441281151793803468150009579234152846302559876786023474384116741665435201433229827460838178073195265052758445179713180253281489421418956836612831335004147646176505141530943528324883137600012405638129713792381026483382453797745572848181778529230302846010343984669300346417859153737685586930651901846172995428426406351792520589303063891856952065344275226656441810617840991639119780740882869045853963976689135919705280633103928107644634342854948241774287922955722249610590503749361988998785615792967601265193388327434138142757694869631012949844904296215183578755943228774880949418421910124192610317509870035781434478472005580772585827964297458804686746351314049144529869398920254976283223212237757896308731212074522690246629595868795188862406555084509923061745551806883194011498591777868205642389994190989922575357099560320535514451309411366278194983648543644619059240366558012360910031565467287852389667920753931835645260421");
Integer sec_mul("0x15ba06219067ebfbe9ed0b5f446f1dca81c3276915b6cd27621bfefe5cf287146c108442d6a292d7fb2a74fe560c1a57ada6d586250ecf339ee05bc86b762a448c18748c701f15d1ec5c5d1e18e406cfda1466300c5e6bcfe3133b03f296c219c1064da6d8108cbb4974d697faacc1d84207b4554accc45654225bf1dd257726eab616a1abe7e49e1182fb3ad8530b90bad454fe27088653fee80dd11dce148490c5344b0bb307050d35ff2fccaeff59f754bc2b28d780fc328e801f5b9371c35f12916f2ba89b3ae9c16e3fbaaf9a45e59b25b34ac1e0650cc6989ca7e3cac5f80feefd47c5ae684f6b82c45c735d57d884519e52eae19ee41e9aa9d336451e");

```

An example of log and script output can be found in [log_parsing](/log_parsing) folder. 

One can easily see that the exponent is 3072 bits in length, which is a lot longer than expected (2048). Obvisouly, since exponent is periodic, it can be extended to any length. It can be also confirmed that this is not a complete exponent, since the first bignum-like structure in the function does not match the encryption input. (Decryption of the RSA is easily done using public exponent, 65537). There is also no linear. or quadratic, or... (I checked polynomials to about 128th power) dependency. Which leads me to the following stage. 

### Descending into despair 

### Code lifting

### FaIlUrEs uPoN fAiLuReS

### Conclusion

### Some references

https://datatracker.ietf.org/doc/html/rfc3447#page-36


https://patentimages.storage.googleapis.com/0c/f3/c0/08ce4394385810/US20160328543A1.pdf

