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

### Reverse enginering and emulating

### Extracting part of the exponent

### Descending into despair 

### Code lifting

### FaIlUrEs uPoN fAiLuReS

### Conclusion


