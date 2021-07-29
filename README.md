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

### Descending into despair 

### Code lifting

### FaIlUrEs uPoN fAiLuReS

### Conclusion

### Some references

https://datatracker.ietf.org/doc/html/rfc3447#page-36



