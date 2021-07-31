
#include <iostream>
#include <sstream>
#include <iomanip>

#include "cryptlib.h"

#include "filters.h"
#include "modarith.h"
#include "codelift.h"
using namespace CryptoPP;
typedef unsigned char byte;
typedef unsigned long long UINT64;

std::string hexStr(byte* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}


#define undefined void
#define undefined4 uint32_t
typedef  unsigned int uint;
uint64_t a;
typedef uint64_t ulonglong;
typedef int64_t longlong;
typedef int64_t undefined8;

int DAT_aaaaaaaaaaaaaaaa = 0xaa;
#define CDM_CLASS_API 
#include "longconsts.h"

Integer main_n("0xBCA83D793F493C49DF558612E74C773198AB4901F20369BFAF1598D71E362EF13AB9BE3B4D4D73C63378542D23BEBA56AD4D589C1E7F151E25CF6F7A38F8FF1FF491D5D2DFC971617B6D9559406E3A5127B2AEBDDEA965E0DFCF4C50AE241CAF9E87BFE33B0DB619B5C395E3986E310A3278F990B4139A421AF74B3E4E1548250DEC8F1755B038E61069E2547983ED93878549B4A9F5FAA1BEF72A75A9929FA7240FB1E46B9587170EF993C29C35F1F145E55BFEC0DE85D2B9409D6599B1C348BF76DD441ABD53033475E3267F91647C2584D974D3AD7B8C0C33711556D6C2CF23BF7905B17A68C622A0580A623C1AF9F446294D5F2DE50721D85EB5F49B7013");
Integer sec_pwr("3551441281151793803468150009579234152846302559876786023474384116741665435201433229827460838178073195265052758445179713180253281489421418956836612831335004147646176505141530943528324883137600012405638129713792381026483382453797745572848181778529230302846010343984669300346417859153737685586930651901846172995428426406351792520589303063891856952065344275226656441810617840991639119780740882869045853963976689135919705280633103928107644634342854948241774287922955722249610590503749361988998785615792967601265193388327434138142757694869631012949844904296215183578755943228774880949418421910124192610317509870035781434478472005580772585827964297458804686746351314049144529869398920254976283223212237757896308731212074522690246629595868795188862406555084509923061745551806883194011498591777868205642389994190989922575357099560320535514451309411366278194983648543644619059240366558012360910031565467287852389667920753931835645260421");
Integer sec_mul("0x15ba06219067ebfbe9ed0b5f446f1dca81c3276915b6cd27621bfefe5cf287146c108442d6a292d7fb2a74fe560c1a57ada6d586250ecf339ee05bc86b762a448c18748c701f15d1ec5c5d1e18e406cfda1466300c5e6bcfe3133b03f296c219c1064da6d8108cbb4974d697faacc1d84207b4554accc45654225bf1dd257726eab616a1abe7e49e1182fb3ad8530b90bad454fe27088653fee80dd11dce148490c5344b0bb307050d35ff2fccaeff59f754bc2b28d780fc328e801f5b9371c35f12916f2ba89b3ae9c16e3fbaaf9a45e59b25b34ac1e0650cc6989ca7e3cac5f80feefd47c5ae684f6b82c45c735d57d884519e52eae19ee41e9aa9d336451e");

void MB_Zeropad_180113d26(int len1, byte* data1, uint param_3, byte* output)
{
    int iVar1;
    ulonglong uVar2;
    int iVar3;
    byte bVar4;
    uint uVar5;
    uint uVar6;
    ulonglong uVar7;

    uVar5 = param_3 + 7;
    uVar6 = param_3 + 0xe;
    if (-1 < (int)uVar5) {
        uVar6 = uVar5;
    }
    uVar6 = (int)uVar6 >> 3;
    if (-1 < (int)param_3) {
        uVar5 = param_3;
    }
    iVar3 = param_3 - (uVar5 & 0xfffffff8);
    if (0 < (int)param_3) {
        iVar1 = len1 + 0xe;
        if (-1 < len1 + 7) {
            iVar1 = len1 + 7;
        }
        uVar7 = 1;
        if (1 < (int)uVar6) {
            uVar7 = (ulonglong)uVar6;
        }
        uVar2 = 0;
        do {
            if ((longlong)uVar2 < (longlong)(iVar1 >> 3)) {
                bVar4 = data1[uVar2];
            }
            else {
                bVar4 = 0;
            }
            output[uVar2] = bVar4;
            uVar2 = uVar2 + 1;
        } while (uVar7 != uVar2);
    }
    if (0 < iVar3) {
        output[(longlong)(int)uVar6 + -1] =
            output[(longlong)(int)uVar6 + -1] & ~(byte)(-1 << ((byte)iVar3 & 0x1f));
    }
    return;
}

byte* PFUN_180119595(byte* param_1, byte* param_2, uint length, int param_4)

{
    byte* pbVar1;
    uint uVar2;
    ulonglong uVar3;
    uint uVar4;
    uint uVar5;
    ulonglong uVar6;
    bool bVar7;

    uVar6 = (ulonglong)(length * 4);
    if (param_2[uVar6] != '\x02') {
        do {
            pbVar1 = param_2 + uVar6;
            bVar7 = *pbVar1 == 0;
            *pbVar1 = *pbVar1 ^ bVar7 * (*pbVar1 ^ 1);
        } while ((byte)(!bVar7 * *pbVar1) == '\x01');
        if (bVar7) {
            if (length != 0) {
                uVar5 = param_4 * 0xe286515;
                uVar3 = 0;
                do {
                    uVar2 = *(uint*)(param_1 + uVar3 * 4);
                    uVar4 = uVar2 ^ uVar5;
                    *(uint*)(param_2 + uVar3 * 4) = uVar4;
                    uVar5 = uVar5 + uVar2 * uVar4;
                    uVar3 = uVar3 + 1;
                } while (length != uVar3);
            }
            param_2[uVar6] = '\x02';
        }
    }
    return param_2;
}
byte DAT_18064e850[32] = { 0xF1, 0xD8, 0x45, 0xD1 ,0xD0, 0x23, 0xB4, 0x16 , 0xDC, 0x61, 0x84, 0xB4,
0x92, 0xD, 0x72, 0x3E , 0x56, 0x96, 0x2C, 0x4E ,0xFD, 0x57, 
0xD0, 0x3D ,0xF8, 0x8, 0xB6, 0x1B , 0xD1, 0xB2, 0x1A, 0xDD };

byte DAT_180bb70d4[35] = { 0 };


uint* PFUN_180119595(uint* param_1, uint* out, uint length, int param_4)
{
    byte* pbVar1;
    uint uVar2;
    ulonglong uVar3;
    uint uVar4;
    uint uVar5;
    ulonglong uVar6;
    bool bVar7;

    uVar6 = (ulonglong)(length * 4);
    if (*(char*)((longlong)out + uVar6) != '\x02') {
        do {
           
            pbVar1 = (byte*)((longlong)out + uVar6);
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
            *(byte*)((longlong)out + uVar6) = 2;
        }
    }
    return out;
}
void ConstUser_18016b077(ulonglong constant, byte* pdat, byte* param_3, byte* output)

{
    uint uVar1;
    uint uVar2;
    ulonglong uVar3;
    ulonglong offset;
    ulonglong uVar4;
     
    offset = (ulonglong)((uint)constant & 0x3fffff);

    uVar1 = (uint)(constant >> 0x24) & 0x3fff;
    if (uVar1 == 0) {
        uVar4 = 0;
        uVar1 = 0;
    }
    else {
        uVar4 = (ulonglong)uVar1;
        uVar3 = 0;
        uVar1 = 0;
        do {
            uVar2 = uVar1 & 0xf8;
            uVar1 = (uint)(byte)(DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[offset + uVar3] << 0xb ^
                ((ulonglong)param_3[uVar3] << 8 |
                    (ulonglong)uVar2 ^ (ulonglong)pdat[uVar3])];
            output[uVar3] =
                (DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[offset + uVar3] << 0xb ^
                ((ulonglong)param_3[uVar3] << 8 | (ulonglong)uVar2 ^ (ulonglong)pdat[uVar3])] & 7;
            uVar3 = uVar3 + 1;
        } while (uVar4 != uVar3);
    }
    /* Looks similar but without offset? */
    if (constant >> 0x32 != 0) {
        uVar3 = 0;
        do {
            uVar2 = uVar1 & 0xf8;
            uVar1 = (uint)(byte)(DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[uVar3 + offset + uVar4] << 0xb ^
                ((ulonglong)param_3[uVar3 + uVar4] << 8 | (ulonglong)uVar2)];
            output[uVar3 + uVar4] =
                (DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[uVar3 + offset + uVar4] << 0xb ^
                ((ulonglong)param_3[uVar3 + uVar4] << 8 | (ulonglong)uVar2)] & 7;
            uVar3 = uVar3 + 1;
        } while (constant >> 0x32 != uVar3);
    }
    return;
}

void OtherConstUser_180169484(ulonglong param_1, byte* param_2, byte* param_3, byte* param_4)

{
    uint uVar1;
    ulonglong uVar2;
    ulonglong uVar3;
    ulonglong uVar4;
    ulonglong uVar5;
    uint uVar6;

    uVar4 = (ulonglong)((uint)param_1 & 0x3fffff);
    uVar6 = (uint)(param_1 >> 0x24) & 0x3fff;
    if ((param_1 >> 0x16 & 0x3fff) == 0) {
        uVar5 = 0;
        uVar1 = 0;
    }
    else {
        uVar5 = (ulonglong)((uint)(param_1 >> 0x16) & 0x3fff);
        uVar3 = 0;
        uVar1 = 0;
        do {
            uVar1 = (uint)(byte)(DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[uVar4 + uVar3] << 0xb ^
                ((ulonglong)param_3[uVar3] << 8 |
                    (ulonglong)(uVar1 & 0xf8) ^ (ulonglong)param_2[uVar3])];
            uVar3 = uVar3 + 1;
        } while (uVar5 != uVar3);
    }
    if (uVar6 == 0) {
        uVar3 = 0;
    }
    else {
        uVar3 = (ulonglong)uVar6;
        uVar2 = 0;
        do {
            uVar6 = uVar1 & 0xf8;
            uVar1 = (uint)(byte)(DAT_1809cde30)
                [(uint)(byte)(DAT_180a25040)[uVar2 + uVar5 + uVar4] << 0xb ^
                ((uint)param_3[uVar2 + uVar5] << 8 | uVar6 ^ param_2[uVar2 + uVar5])];
            param_4[uVar2] =
                (DAT_1809cde30)
                [(uint)(byte)(DAT_180a25040)[uVar2 + uVar5 + uVar4] << 0xb ^
                ((uint)param_3[uVar2 + uVar5] << 8 | uVar6 ^ param_2[uVar2 + uVar5])] & 7;
            uVar2 = uVar2 + 1;
        } while (uVar3 != uVar2);
    }
    if (param_1 >> 0x32 != 0) {
        uVar2 = 0;
        do {
            uVar6 = uVar1 & 0xf8;
            uVar1 = (uint)(byte)(DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[uVar2 + uVar5 + uVar3 + uVar4] << 0xb |
                (ulonglong)uVar6];
            param_4[uVar2 + uVar3] =
                (DAT_1809cde30)
                [(ulonglong)(byte)(DAT_180a25040)[uVar2 + uVar5 + uVar3 + uVar4] << 0xb |
                (ulonglong)uVar6] & 7;
            uVar2 = uVar2 + 1;
        } while (param_1 >> 0x32 != uVar2);
    }
    return;
}

unsigned char OFSB(short a)
{
    if (a < 0) return 0;
    if (a > 255) return 255;
    return (unsigned char)a;
}
class reg16
{
public:
    unsigned char data[16];
    void assign4(uint dat)
    {
        memset(data, 0, 16);
        *(uint*)data = dat;
    }
    void assign8(ulonglong dat)
    {
        memset(data, 0, 16);
        *(ulonglong*)data = dat;
    }
    void PACKUSWB(reg16& other)
    {
        unsigned char dts[16];
        short* a1 = (short*)data;
        short* a2 = (short*)other.data;
        dts[0] = OFSB(a1[0]);
        dts[1] = OFSB(a1[1]);
        dts[2] = OFSB(a1[2]);
        dts[3] = OFSB(a1[3]);
        dts[4] = OFSB(a1[4]);
        dts[5] = OFSB(a1[5]);
        dts[6] = OFSB(a1[6]);
        dts[7] = OFSB(a1[7]);

        dts[8] = OFSB(a2[0]);
        dts[9] = OFSB(a2[1]);
        dts[10] = OFSB(a2[2]);
        dts[11] = OFSB(a2[3]);
        dts[12] = OFSB(a2[4]);
        dts[13] = OFSB(a2[5]);
        dts[14] = OFSB(a2[6]);
        dts[15] = OFSB(a2[7]);
        memcpy(data, dts, 16);
    }
    void PUNPCKHQDQ(reg16& other)
    {
        unsigned long long* d1 = (unsigned long long*)data;
        unsigned long long* d2 = (unsigned long long*)other.data;
        d1[0] = d1[1];
        d1[1] = d2[1];
    }
    void PUNPCKLQDQ(reg16& other)
    {
        unsigned long long* d1 = (unsigned long long*)data;
        unsigned long long* d2 = (unsigned long long*)other.data;
        d1[1] = d2[0];
    }

    void PADDD(reg16& other)
    {
        uint* d1 = (uint*)data;
        uint* d2 = (uint*)other.data;
        d1[0] = d1[0] + d2[0];
        d1[1] = d1[1] + d2[1];
        d1[2] = d1[2] + d2[2];
        d1[3] = d1[3] + d2[3];
    }
    void ANDPS(reg16& other)
    {
        uint* d1 = (uint*)data;
        uint* d2 = (uint*)other.data;
        d1[0] =( d1[0] & d2[0]);
        d1[1] =( d1[1] & d2[1]);
        d1[2] =( d1[2] & d2[2]);
        d1[3] =( d1[3] & d2[3]);
    }
    void ANDPD(reg16& other)
    {
        unsigned long long* d1 = (unsigned long long*)data;
        unsigned long long* d2 = (unsigned long long*)other.data;
        d1[0] = (d1[0] & d2[0]);
        d1[1] = (d1[1] & d2[1]);
      }
    void PSLLD(uint shift)
    {
        uint* d1 = (uint*)data;
  
        d1[0] = d1[0] << shift;
        d1[1] = d1[1] << shift;
        d1[2] = d1[2] << shift;
        d1[3] = d1[3] << shift;
    }
    void PSRLD(uint shift)
    {
        uint* d1 = (uint*)data;

        d1[0] = d1[0] >> shift;
        d1[1] = d1[1] >> shift;
        d1[2] = d1[2] >> shift;
        d1[3] = d1[3] >> shift;
    }
    void PADDQ(reg16& other)
    {
        ulonglong* d1 = (ulonglong*)data;
        ulonglong* d2 = (ulonglong*)other.data;
        d1[0] = d1[0] + d2[0];
        d1[1] = d1[1] + d2[1];

    }
    void PSRLQ(uint shift)
    {
        ulonglong* d1 = (ulonglong*)data;
     
        d1[0] = d1[0] >>shift;
        d1[1] = d1[1] >>shift;

    }
    void PSLLQ(uint shift)
    {
        ulonglong* d1 = (ulonglong*)data;

        d1[0] = d1[0] << shift;
        d1[1] = d1[1] << shift;

    }
    void PUNPCKLBW(reg16& other)
    {
        data[15] = other.data[7];
        data[14] = data[7];
        data[13] = other.data[6];
        data[12] = data[6];
        data[11] = other.data[5];
        data[10] = data[5];
        data[9] = other.data[4];
        data[8] = data[4];
        data[7] = other.data[3];
        data[6] = data[3];
        data[5] = other.data[2];
        data[4] = data[2];
        data[3] = other.data[1];
        data[2] = data[1];
        data[1] = other.data[0];
    }
    void PUNPCKLWD(reg16& other)
    {
        short* d1 = (short*)data;
        short* d2 = (short*)other.data;
        d1[7] = d2[3];
        d1[6] = d1[3];
        d1[5] = d2[2];
        d1[4] = d1[2];
        d1[3] = d2[1];
        d1[2] = d1[1];
        d1[1] = d2[0];
    }
    void CVTTPS2DQ(reg16& other)
    {
        float* f1 = (float*)other.data;
        int res[4];
        res[0] = (int)f1[0];
        res[1] = (int)f1[1];
        res[2] = (int)f1[2];
        res[3] = (int)f1[3];
        memcpy(data, res, 16);
    }

    void PSHUFD(reg16& other, int mask)
    {
        uint32_t* d1 = (uint32_t*)data;
        uint32_t* d2 = (uint32_t*)other.data;
        uint32_t temp[4];
        temp[0] = d2[mask & 3];
        mask >>= 2;
        temp[1] = d2[mask & 3];
        mask >>= 2;
        temp[2] = d2[mask & 3];
        mask >>= 2;
        temp[3] = d2[mask & 3];
        d1[0] = temp[0];
        d1[1] = temp[1];
        d1[2] = temp[2];
        d1[3] = temp[3];
    }
    /*DEST[31:0]←Select4(SRC1[127:0], imm8[1:0]);
DEST[63:32]←Select4(SRC1[127:0], imm8[3:2]);
DEST[95:64]←Select4(SRC2[127:0], imm8[5:4]);
DEST[127:96]←Select4(SRC2[127:0], imm8[7:6]);
DEST[MAXVL-1:128] (Unmodified)*/
    void SHUFPS(reg16& other, int mask)
    {
        float* d1 = (float*)data;
        float* d2 = (float*)other.data;
        float temp[4];
        temp[0] = d1[mask & 3];
        mask >>= 2;
        temp[1] = d1[mask & 3];
        mask >>= 2;
        temp[2] = d2[mask & 3];
        mask >>= 2;
        temp[3] = d2[mask & 3];
        d1[0] = temp[0];
        d1[1] = temp[1];
        d1[2] = temp[2];
        d1[3] = temp[3];
    }
    void PMULUDQ(reg16& other)
    {
        uint32_t* d1 = (uint32_t*)data;
        uint32_t* d2 = (uint32_t*)other.data;
        uint64_t* res = (uint64_t*)data;
        uint64_t o1 = d1[0];
        uint64_t o2 = d2[0];
        res[0]= o1 * o2;
        o1 = d1[2];
        o2 = d2[2];
        res[1] = o1 * o2;

    }
    void PUNPCKLDQ(reg16& other)
    {
        uint32_t* d1 = (uint32_t*)data;
        uint32_t* d2 = (uint32_t*)other.data;
        d1[3] = d2[1];
        d1[2] = d1[1];
        d1[1] = d2[0];

    }
    void POR(reg16& other)
    {
        for (int i = 0; i < 16; i++)
        {
            data[i] = (data[i]|other.data[i]);
        }
    }
    void PAND(reg16& other)
    {
        for (int i = 0; i < 16; i++)
        {
            data[i] = (data[i] & other.data[i]);
        }
    }

};

void Maybe_MEMSET_180512a50(void* buf, byte st, size_t len)
{
    memset(buf, st, len);
}

typedef unsigned short ushort;

void YA_ConstUser_18019c44f(ulonglong param_1, byte* param_2, byte* param_3)

{
    longlong lVar1;
    uint uVar2;
    ulonglong uVar3;
    uint uVar4;
    ulonglong uVar5;

    uVar5 = (ulonglong)param_1;
    lVar1 = 0;
    uVar4 = 0;
    do {
        uVar2 = (uint) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[uVar5 + lVar1] << 0xc |
                    (ulonglong)(uVar4 & 0xff8) ^ (ulonglong)param_2[lVar1]) * 2);
        uVar4 = (uint) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[uVar5 + lVar1] << 0xc |
                    (ulonglong)(uVar4 & 0xff8) ^ (ulonglong)param_2[lVar1]) * 2);
        lVar1 = lVar1 + 1;
    } while (lVar1 != 3);
    lVar1 = 0;
    do {
        uVar4 = uVar2 & 0xff8;
        uVar2 = (uint) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[lVar1 + uVar5+3] << 0xc |
                    (ulonglong)uVar4 ^ (ulonglong)param_2[lVar1 + 3]) * 2);
        param_3[lVar1] =
            (byte) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[lVar1 + uVar5+3] << 0xc |
                    (ulonglong)uVar4 ^ (ulonglong)param_2[lVar1 + 3]) * 2) & 7;
        lVar1 = lVar1 + 1;
    } while (lVar1 != 3);
    lVar1 = 0;
    do {
        uVar3 = (ulonglong)uVar2;
        uVar2 = (uint) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[lVar1 + uVar5+6] << 0xc ^
                    param_2[lVar1 + 2] ^ uVar3) * 2);
        param_3[lVar1 + 3] =
            (byte) * (ushort*)
            (DAT_180b2f040 +
                ((ulonglong)(byte)(DAT_180a25040)[lVar1 + uVar5+6] << 0xc ^
                    param_2[lVar1 + 2] ^ uVar3) * 2) & 7;
        lVar1 = lVar1 + 1;
    } while (lVar1 != 3);
    return;
}
void Spec_Const_user_18019c3f4(ulonglong param_1, byte* param_2, byte* param_3, byte* param_4)

{
    longlong lVar1;
    uint uVar2;
    uint uVar3;

    lVar1 = 0;
    uVar3 = 0;
    do {
        uVar2 = uVar3 & 0xf8;
        uVar3 = (uint)(byte)(DAT_1809cde30)
            [(ulonglong)(byte)(DAT_180a25040)[(param_1 & 0xffffffff) + lVar1] << 0xb ^
            ((ulonglong)param_3[lVar1] << 8 |
                (ulonglong)uVar2 ^ (ulonglong)param_2[lVar1])];
        param_4[lVar1] =
            (DAT_1809cde30)
            [(ulonglong)(byte)(DAT_180a25040)[(param_1 & 0xffffffff) + lVar1] << 0xb ^
            ((ulonglong)param_3[lVar1] << 8 | (ulonglong)uVar2 ^ (ulonglong)param_2[lVar1])] & 7;
        lVar1 = lVar1 + 1;
    } while (lVar1 != 6);
    return;
}
void YA_Const_C_User_18019c50b(ulonglong param_1, byte* param_2, byte* param_3)

{
    uint uVar1;
    ulonglong uVar2;
    ulonglong uVar3;
    ulonglong uVar4;
    uint uVar5;
    ulonglong uVar6;
    uint uVar7;

    uVar4 = (ulonglong)((uint)param_1 & 0x3fffff);
    uVar7 = (uint)(param_1 >> 0x24) & 0x3fff;
    uVar5 = (uint)(param_1 >> 0x16) & 0x3fff;
    if ((param_1 >> 0x16 & 0x3fff) == 0) {
        uVar6 = 0;
        uVar1 = 0;
    }
    else {
        uVar6 = (ulonglong)uVar5;
        uVar3 = 0;
        uVar1 = 0;
        do {
            uVar1 = (uint) * (ushort*)
                (DAT_180b2f040 +
                    ((ulonglong)(byte)(DAT_180a25040)[uVar4 + uVar3] << 0xc |
                        (ulonglong)(uVar1 & 0xff8) ^ (ulonglong)param_2[uVar3]) * 2);
            uVar3 = uVar3 + 1;
        } while (uVar6 != uVar3);
    }
    if (uVar7 == 0) {
        uVar3 = 0;
    }
    else {
        uVar3 = (ulonglong)uVar7;
        uVar2 = 0;
        do {
            uVar7 = uVar1 & 0xff8;
            uVar1 = (uint) * (ushort*)
                (DAT_180b2f040 +
                    ((ulonglong)(uVar7 ^ (param_2 + uVar6)[uVar2]) |
                        (ulonglong)(byte)(DAT_180a25040)[uVar2 + uVar6 + uVar4] << 0xc) * 2);
            param_3[uVar2] =
                (byte) * (ushort*)
                (DAT_180b2f040 +
                    ((ulonglong)(uVar7 ^ (param_2 + uVar6)[uVar2]) |
                        (ulonglong)(byte)(DAT_180a25040)[uVar2 + uVar6 + uVar4] << 0xc) * 2) & 7;
            uVar2 = uVar2 + 1;
        } while (uVar3 != uVar2);
    }
    if (param_1 >> 0x32 != 0) {
        uVar2 = 0;
        do {
            uVar7 = (param_2 + uVar6)[uVar2 - (uVar5 - 2)] ^ uVar1;
            uVar1 = (uint) * (ushort*)
                (DAT_180b2f040 +
                    (ulonglong)
                    ((uint)(byte)(DAT_180a25040)[uVar2 + uVar6 + uVar3 + uVar4] << 0xc ^ uVar7) *
                    2);
            param_3[uVar2 + uVar3] =
                (byte) * (ushort*)
                (DAT_180b2f040 +
                    (ulonglong)
                    ((uint)(byte)(DAT_180a25040)[uVar2 + uVar6 + uVar3 + uVar4] << 0xc ^ uVar7) * 2)
                & 7;
            uVar2 = uVar2 + 1;
        } while (param_1 >> 0x32 != uVar2);
    }
    return;
}



void Crazed_18016cddb(byte* param_1, byte* param_2, byte* param_3)

{
 
    uint uVar6;
    byte* pbVar18;
    ulonglong uVar19;
    byte* pbVar20;
    byte local_3980[6500+6*8+ 2594+ 11424];
    byte* abStack14098= local_3980+0x26e;
    byte* abStack11504 = local_3980 + 0xc90;
    //ulonglong uStack72;
    
    Maybe_MEMSET_180512a50((char*)local_3980, 0xaa, 0x3927);
    uVar19 = 50;
    MB_Zeropad_180113d26(0x2010, param_1, 0x2010, abStack11504 + uVar19);
    pbVar20 = abStack14098 + uVar19;
    MB_Zeropad_180113d26(0x2010, param_2, 0x2010, pbVar20);
    // 3980: rsp+0x30 abStack11504: rsp+ 0xcc0 (3980+c90)  abStack14098:  0x29e
    pbVar18 = local_3980 + uVar19; //r12
    byte* c_offset = Jumper_18135b4c0;
    int cjump = 287; 
    while (true)
    {
        switch (cjump)
        {
        case 0:
        {
            MB_Zeropad_180113d26(0x2010, pbVar20, 0x2010, param_3);
            return;
        }
        case 287: 
        {
            UINT64 par1 = *(UINT64*)c_offset;
            byte * par2= pbVar18+ *(short*)(c_offset+8);
            byte* par3= pbVar18 +  *(short*)(c_offset + 10);
            byte* par4 = pbVar18 + *(short*)(c_offset + 12);
            cjump= *(short*)(c_offset + 14);
            ConstUser_18016b077(par1,par2,par3,par4);
            c_offset += 16;
        }; break;
        case 421:
        {
            UINT64 eax = *(UINT64*)c_offset;
            int ebx = 0x1ff;
            byte* rcx = pbVar18 + *(short*)(c_offset + 10);
            cjump = *(short*)(c_offset + 14);

            uint r8d = (uint)(eax & ebx);
            uint esi = (((uint)eax) >> 0x12) & ebx;
            uint r10d = (((uint)eax) >> 0x1b) & 0x7;
            esi--;
            uint ebp = 0;
            if (esi >= r8d)
            {
                byte* r11 = pbVar18 + *(short*)(c_offset + 8);
                eax = (eax >> 9) & ebx;
                ebx = (int)r8d;
                ebx = -ebx;
                do {
                    int edx = ebx + esi;
                    if (edx < eax) 
                    {
                        edx = edx;
                        *(byte*)&edx = r11[edx];
                    }
                    else
                    {
                        edx = 0;
                    }
                    ebp = esi;
                    rcx[ebp] = *(byte*)&edx;
                    esi--;
                } while (esi >= r8d);
            }
            r8d--;
            rcx[r8d]=*(byte*)&r10d;
            if (r8d != 0)
            {
                Maybe_MEMSET_180512a50(rcx, 0, r8d);
            }
            c_offset += 16;
        }; break;
        case 464:
        {
            UINT64 ecx = *(UINT64*)c_offset;
            byte* rdx = pbVar18 + *(short*)(c_offset + 8);
            byte* r8 = pbVar18 + *(short*)(c_offset + 10);
            YA_ConstUser_18019c44f(ecx, rdx, r8);
            cjump = *(short*)(c_offset + 14);
            c_offset += 16;

        }; break;
        case 516:
        {
            UINT64 ecx = *(UINT64*)c_offset;
            byte* rdx = pbVar18 + *(short*)(c_offset + 8);
            byte* r8 = pbVar18 + *(short*)(c_offset + 10);
            byte* r9 = pbVar18 + *(short*)(c_offset + 12);
            Spec_Const_user_18019c3f4(ecx, rdx, r8, r9);
            cjump = *(short*)(c_offset + 14);
            c_offset += 16;
        }; break;
        case 139:
        {
            UINT64 edx = *(UINT64*)c_offset;
            byte* rcx = pbVar18 + *(short*)(c_offset + 10);
            int ebx = 0xfffff;
            long long r8 = edx&ebx;
            long long rax = (edx>>0x28) & ebx;
            long long r10 = (edx >> 0x3c) & 7;
            rax--;
            if (rax >= r8)
            {
                byte* r11 = pbVar18 + *(short*)(c_offset + 8);
                edx = edx >> 0x14;
                edx = edx & ebx;
                ebx = (int)r8;
                ebx = -ebx;
                do {
                    int esi = (int)(rax + ebx);
                    if (esi <= edx)
                    {
                        *(byte*)&esi = r11[esi];
                    }
                    else
                    {
                        esi = 0;
                    }
                    rcx[rax] = *(byte*)&esi;
                    rax--;
                } while (rax>=r8);

            }
            r8--;
            rcx[r8] = *(byte*)&r10;
            if (r8 != 0)
            {
                Maybe_MEMSET_180512a50(rcx, 0, r8);
            } //this all looks like inersion with zero-extension
            cjump = *(short*)(c_offset + 14);
            c_offset += 16;
        }; break;
        case 183:
        {
            UINT64 ecx = *(UINT64*)c_offset;
            byte* rdx = pbVar18 + *(short*)(c_offset + 8);
            byte* r8 = pbVar18 + *(short*)(c_offset + 10);
            YA_Const_C_User_18019c50b(ecx,rdx,r8);
            cjump = *(short*)(c_offset + 14);
            c_offset += 16;
        }; break;
        case 235:
        {
            UINT64 ecx = *(UINT64*)c_offset;
            byte* rdx = pbVar18 + *(short*)(c_offset + 8);
            byte* r8 = pbVar18 + *(short*)(c_offset + 10);
            byte* r9 = pbVar18 + *(short*)(c_offset + 12);
            OtherConstUser_180169484(ecx, rdx, r8, r9);
            cjump = *(short*)(c_offset + 14);
            c_offset += 16;
        }; break;
        }
    }

}



void SetOthConstCarry_1801a5bb6(uint offset, longlong* output)

{
    uint uVar1;
    ulonglong uVar2;
    ulonglong uVar3;
    int iVar4;
    longlong lVar5;

    uVar1 = offset + 7;
    if (-1 < (int)offset) {
        uVar1 = offset;
    }
    lVar5 = (longlong)(int)(offset - (uVar1 & 0xfffffff8));
    uVar3 = (ulonglong)
        (( (int)INT_18091c050[(int)offset] * (int)INT_18091ce30[lVar5] + INT_18091ce50[lVar5]) *
            -0x11ed51cb - 0x8cd05);
    uVar2 = uVar3 * 0x1ea03e336084a9cb + 0x86cb28d431493520;
    iVar4 = 8;
    do {
        uVar2 = (uVar2 >> 4) + (QWORD_18091ce70)[(uint)uVar2 & 0xf];;
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *output = uVar2 * -0x569769bd00000000 + uVar3 * -0x2ac0fc6afbad6221 + 0x441d2cbc8cfeca4f;
    return;
}


void ECCarry_1801a6406(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091f830)[lVar2] +
            (INT_18091f850)[lVar2]) * 0x62c773e3 + 0x30c8819b);
    uVar3 = uVar5 * -0x19d0b37619fb0e91 + 0xce299419f9bd4629;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091f870)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x26b68e8300000000 + uVar5 * -0x78da670d915d1dcd + -0x3625eaab085c293;
    return;
}


void ECCarry_1801a64a8(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091f8f0)[lVar2] +
            (INT_18091f910)[lVar2]) * 0x42a3d2ab + 0x5010bf8);
    uVar3 = uVar5 * -0x43221e093e2f25a9 + 0xf4a24cccbadb86ec;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091f930)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x2aed998500000000 + uVar5 * 0x13f758f5137591cd + -0x120b2717b6d2d98e;
    return;
}


void SettCarry_1801a5c63(int* param_1, int param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[param_2] * (INT_18091cef0)[lVar2] + (INT_18091cf10)[lVar2]) * -0x66c17717 +
            0x8b70ef88);
    uVar3 = uVar5 * 0x13aba546387c0a0f + 0x689bbdd6ab0a8b17;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091cf30)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x240405c500000000 + uVar5 * 0x381f6810d81df775 + -0x1cb16c6942034c02;
    return;
}

int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}
void hex2bin(const char* src, char* target)
{
    while (*src && src[1])
    {
        *(target++) = char2int(*src) * 16 + char2int(src[1]);
        src += 2;
    }
}


int __meta = 0;
bool __metaskip1 = false;
void SetCarryFromConst_1801a5d05(int param_1, longlong* param_2)

{
    uint uVar1;
    ulonglong uVar2;
    ulonglong uVar3;
    int iVar4;
    longlong lVar5;

    uVar1 = param_1 + 7;
    if (-1 < param_1) {
        uVar1 = param_1;
    }
    lVar5 = (longlong)(int)(param_1 - (uVar1 & 0xfffffff8));
    uVar3 = (ulonglong)
        (((INT_18091c1d0)[param_1] * (INT_18091cfb0)[lVar5] + (INT_18091cfd0)[lVar5]) * 0x2ecdf
            + 0xfb47d83);
    uVar2 = uVar3 * 0x634725c8e05806a3 + 0xad886b4c3504d956;
    iVar4 = 8;
    do {
        uVar2 = (uVar2 >> 4) + QWORD_18091cff0[(uint)uVar2 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_2 = uVar2 * 0x4c45a00d00000000 + uVar3 * 0x34b172b86972c9b9 + 0x1811e7af0d5affa6;
    return;
}

void ECarry_1801a6689(int* param_1, int param_2, longlong* param_3)

{
    longlong lVar1;
    ulonglong uVar2;
    int iVar3;
    ulonglong uVar4;

    lVar1 = (longlong)param_2;
    uVar4 = (ulonglong)
        ((param_1[lVar1] * (INT_180949050)[lVar1] + (INT_180949070)[lVar1]) * -0x20698cfb +
            0x16ba0d03);
    uVar2 = uVar4 * 0x5dd87fd003b2a543 + 0x547e816ab0c0a03a;
    iVar3 = 8;
    do {
        uVar2 = (uVar2 >> 4) + (QWORD_180949090)[(uint)uVar2 & 0xf];
        iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    *param_3 = uVar2 * 0x1afb048300000000 + uVar4 * -0x32116dc985b09d49 + 0x190d79f75bc57aee;
    return;
}

void ECarrys_1801a6d5d(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094b7b0)[lVar2] + (INT_18094b7d0)[lVar2]) * 0x7b0ef5af
            + 0xae94e91d);
    uVar3 = uVar5 * 0x329b9eb17e6ffd6f + 0x3487a1d80659dc32;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094b7f0 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x4647b44300000000 + uVar5 * 0x66ffd927794a600d + 0x3ae77ddb6d5c675;
    return;
}
void ECCarry_1801a60dc(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091e670)[lVar2] +
            (INT_18091e690)[lVar2]) * 0x4f5c0aa3 + 0x8cc137f7);
    uVar3 = uVar5 * -0x6aa8679a5bf10507 + 0xb976a24618f7836a;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091e6b0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x5570576900000000 + uVar5 * 0x369bfd4024a070df + -0x5811cc33c78cb69e;
    return;
}


void ECCarry_1801a603a(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091e5b0)[lVar2] +
            (INT_18091e5d0)[lVar2]) * 0x3314de6b + 0xdb41714);
    uVar3 = uVar5 * 0x55bc900665835331 + 0x3ffc303c1bf5f56a;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091e5f0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x73ac5b7700000000 + uVar5 * 0xe380a3bc68a16c7 + 0x75138567f6ddd0b6;
    return;
}



void Ecarrys_1801a6cbb(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094b6f0)[lVar2] + (INT_18094b710)[lVar2]) * -0x492255bb
            + 0xd4b30d83);
    uVar3 = uVar5 * 0x6b7850b18a3e5087 + 0x8b45c670c15582bb;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094b730 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x719e00bd00000000 + uVar5 * 0x26630ce65a5373ab + -0x1a47412308f2f50c;
    return;
}



void Ya_Carry_1801a5b14(int* param_1, int param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[param_2] * (INT_18091cd70)[lVar2] + (INT_18091cd90)[lVar2]) * 0x3d5174ef +
            0xf1081437);
    uVar3 = uVar5 * 0x7ba08e4729686731 + 0x2170ebedd5b9a01e;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091cdb0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x3b6d35d900000000 + uVar5 * 0x5e34f2fef1b99d89 + 0x65060d3c5fa7a250;
    return;
}

void ECarry_6_1801a6a33(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094a5b0)[lVar2] + (INT_18094a5d0)[lVar2]) * 0x1ba5b281
            + 0x16c9af27);
    uVar3 = uVar5 * 0x751bb89130dfd6ed + 0xa523df752ad642a7;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18094a5f0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x69d23c7b00000000 + uVar5 * -0x540f0f077555cfdf + -0x516761a7e1a3f62d;
    return;
}
void Ecarrys_1801a6ad5(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18094a670)[lVar2] +
            *(int*)(DAT_18094a690 + lVar2 * 4)) * 0x42b3ea81 + 0x17cbfd77);
    uVar3 = uVar5 * -0x76742c88fc58c40d + 0xaef302fd144ee7b3;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094a6b0 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x7c444f0b00000000 + uVar5 * -0x81e6d79bc46f8f + 0x5e638f34188a102d;
    return;
}
Integer deint(unsigned int* de, size_t len)
{
    Integer ret=0;

    for (size_t l = 0; l < len; l++)
    {
        Integer k((byte *)&de[l],4,Integer::UNSIGNED,LITTLE_ENDIAN_ORDER);
        ret = ret + (k<<(32*l));
    }
    return ret;
}
struct SHA1_buf
{
    ulonglong offs;
    byte encbytes[4][66];
    byte encoded1[18];
    byte encoded2[18];
    byte encoded3[18];
    byte encoded4[18];
    byte encoded5[18];
    uint counter;
    char flag;
    uint workspace[16];
    uint prehash;
    uint hash1;
    uint hash2;
    uint hash3;
    uint hash4;
    uint hash5;

};
unsigned char DAT_180909f00[512] = { 85, 77, 119, 222, 84, 50, 254, 32, 171, 89, 140, 215, 255, 21, 22, 41, 249, 21, 44, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 102, 11, 178, 22, 50, 189, 172, 17, 148, 200, 99, 218, 147, 68, 110, 203, 156, 74, 215, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 142, 194, 161, 200, 218, 106, 158, 67, 252, 198, 117, 74, 238, 226, 59, 113, 120, 55, 106, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 161, 223, 95, 153, 229, 158, 29, 86, 229, 158, 239, 89, 224, 154, 67, 217, 71, 39, 133, 215, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 252, 230, 35, 13, 49, 42, 247, 41, 212, 130, 241, 43, 81, 125, 152, 123, 112, 19, 142, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 2, 6, 4, 0, 4, 4, 4, 0, 1, 2, 4, 5, 4, 5, 4, 4, 6, 7, 5, 5, 6, 3, 4, 6, 3, 5, 5, 4, 6, 7, 0, 3, 4, 6, 2, 0, 1, 3, 4, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 0, 2, 6, 7, 5, 4, 5, 0, 3, 5, 4, 6, 2, 6, 3, 4, 6, 4, 4, 0, 0, 0, 0, 6, 0, 2, 4, 5, 4, 0, 3, 6, 2, 5, 0, 1, 2, 6, 3, 6, 2, 0, 7, 6, 3, 0, 7, 6, 3, 6, 3, 0, 7, 4, 6, 1, 7, 0, 7, 5, 5, 6, 3, 6, 2, 4, 5, 4, 6, 1, 7, 4, 5, 0, 2, 5, 4, 6, 2, 4, 1, 4, 4, 6, 4, 0, 0, 5, 7, 2, 4, 0, 5, 3, 2, 5, 6, 2, 4, 0, 7, 5, 6, 3, 6, 3, 4, 0, 1, 2, 4, 5, 5, 6, 2, 6, 2, 0, 7, 4, 4, 5, 5, 5, 0, 7, 0, 2, 4, 6, 3, 6, 7, 4, 6, 1, 1, 2, 5, 0, 2, 5, 4, 6, 3, 6, 5, 1, 3, 2, 4, 0, 0, 0, 0, 4, 6, 5, 1, 2, 0, 4, 5, 7, 3, 5, 5, 5, 4, 4, 6, 2, 4, 0, 7, 4, 6, 1, 7, 6, 2, 6, 3, 0, 1, 3, 4, 0, 7, 5, 0, 1, 7, 6, 3, 6, 2, 4, 0, 3, 4, 0, 1, 2, 5, 5, 6, 1, 3, 4, 4, 4, 3, 5, 6, 4, 6, 0, 0, 0, 0, 4, 6, 5, 7, 2, 0, 4, 5, 1, 1, 2, 4, 6, 6, 2, 6, 3, 4, 5, 0, 2, 6, 1, 7, 6, 2, 4, 4, 5, 5, 4, 6, 7, 0, 1, 7, 5, 5, 6, 3, 6, 3, 6, 1, 3, 4, 0, 1, 2, 0, 7, 6, 7, 6, 3, 6, 2, 5, 3, 2, 4, 6, 0, 0, 5, 1, 2, 6, 5, 7, 2, 5, 3, 1, 7, 7, 3, 3, 2 };

byte DAT_1812f159c[25] = { 0 };
byte DAT_1812f15b4[25] = { 0 };
byte DAT_1812f15cc[25] = { 0 };
byte DAT_1812f15e4[25] = { 0 };
byte DAT_1812f15fc[25] = { 0 };


//6aaa96a5a5699aa6aaaa95659596aa9555aa6a56 : ab
//9555695a5a96655955556a9a6a69556aaa5595a9 : a0
//c0006c1b1ac7701c00006adb6b6c006aab01c1ad : af
//c0006c1b1ac7701c00006adb6b6c006aab01c1a8 : "first" changed to 0

unsigned char DAT_18053c6c0[16] = { 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 };
unsigned char DAT_18064cd50[16] = { 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
unsigned char DAT_18064cda0[16] = { 0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63 };
unsigned char DAT_18064cdb0[16] = { 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0 };


/// (0x)00 00 00 00 00 00 00 00 || mHash||salt

void FillRandom_1801a741c(byte* buf, ulonglong len)
{
    memset(buf, 0xaf, len);
    //nice and random :P

}

void Divshuffler_18011411d(byte* param_1, int param_2, byte* param_3)

{
    uint uVar1;
    uint uVar2;
    ulonglong uVar3;

    uVar2 = param_2 - 2;
    if (uVar2 != 0) {
        uVar1 = 0x3191;
        uVar3 = 0;
        do {
            param_3[uVar3] = param_1[uVar1 % uVar2 + 2];
            uVar1 = uVar1 % uVar2 + 0x81df;
            uVar3 = uVar3 + 1;
        } while (uVar2 != uVar3);
    }
    return;
}

void WShuffle_1801140e2(byte* param_1, int param_2, byte* param_3)

{
    uint uVar1;
    uint uVar2;
    ulonglong uVar3;

    uVar2 = param_2 - 2;
    *(short*)param_3 = (short)uVar2;
    if (uVar2 != 0) {
        uVar1 = 0x3191;
        uVar3 = 0;
        do {
            param_3[uVar1 % uVar2 + 2] = param_1[uVar3];
            uVar1 = uVar1 % uVar2 + 0x81df;
            uVar3 = uVar3 + 1;
        } while (uVar2 != uVar3);
    }
    return;
}

/*
   1.  If the length of M is greater than the input limitation for the
       hash function (2^61 - 1 octets for SHA-1), output "message too
       long" and stop.
   2.  Let mHash = Hash(M), an octet string of length hLen.
   3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
   4.  Generate a random octet string salt of length sLen; if sLen = 0,
       then salt is the empty string.
   5.  Let
         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
       M' is an octet string of length 8 + hLen + sLen with eight
       initial zero octets.
   6.  Let H = Hash(M'), an octet string of length hLen.
   7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
       zero octets.  The length of PS may be 0.
   8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
       emLen - hLen - 1.*/
// this does the whole oaeap signing, so must include SHA1 hash somewhere... 
// That part was mostly removed since it did not contribute to the input encoding, and was thus useless for decryption

byte __metaSafetable[1026];
void Crazery_18016c170(char* param_1, char* randomized, byte* param_3, byte* param_4, byte* param_5,
    byte* param_6)

{
    ulonglong uVar11;
    byte* local_7020; //0x40
    byte* local_6ff0;//0x70
    byte* local_6fe8; //0x78
    byte* local_6fe0= param_3;
    byte lv90[0x800];
    byte lv890[0x800];//890
    byte local_5fd0[0x5f7b];//0x1090
    byte* auStack19476 = local_5fd0 + 0x244c-0x1090;
    byte*  auStack14988 = local_5fd0 + 0x35d4-0x1090;

    Maybe_MEMSET_180512a50((char*)local_5fd0, 0, 0x5f7b);
    uVar11 = 0x8a;
    local_7020 = local_5fd0 + uVar11;
    WShuffle_1801140e2((byte*)param_1, 0x54, (byte *)((longlong)auStack19476 + uVar11));//local_7020+5052 first byte is length
    WShuffle_1801140e2((byte*)randomized, 0x54, (byte*)((longlong)auStack14988 + uVar11));//local_7020+9540
    MB_Zeropad_180113d26(0x97c0, DAT_1812f16b0, 0x97c0, local_7020); //4856 end? 
    local_6fe8 = local_7020 + 2;
    local_6ff0 = local_5fd0 + uVar11 + 2;
    int cjump = 0x812;
    byte* coffset = DAT_1812f29b0; //rsp+0x20, r11
    ulonglong lc38;
    long long ert = 0;
    *(short*)(local_7020 + 15056) = 1026;
    *(short*)(local_7020 + 7528) = 1026;
    *(short*)(local_7020 + 11216) = 1026;
    *(short*)(local_7020 + 3580) = 1026;
    *(short*)(local_7020 + 1488) = 1026;
    *(short*)(local_7020 + 19940) = 1026;
    memset(local_7020 + 15058, 4, 1026);
    memset(local_7020 + 7530, 4, 1026);
    memset(local_7020 + 11218, 3, 1026); 
    memset(local_7020 + 3582, 4, 1026);
    memset(local_7020 + 1490, 4, 1026);
   // hex2bin("040502060305070002050200000200010607060706040407000402010001040703030600050101050306030503060307050006060002070100030100020602030404010700030005000400070504010606050000060704030100020700000102010400020003040500060005070101010502000002050504050702030400000305070305010200010006070707050506020103030407070001000305010202000602010105030004030300040303010705010602010600030305040402060404000106030506050707050502010301030205000200010105030202040005070701010201010306000205050702010007020007010405020006070203010105010706010401030103040503010302040701030104060204040405070307030504010007070200000107050206040002060105070600020006010606020301070002060207000703050706040600050700010200060301010600000502070302030504030204050701020704040705050203030507040104060306000207000502000005030301000301060603030004000605010103040004020007020205070602000601030305040305060404040704010606000600030506040705030302030705000307070103000601070007030205050500000403040203040406040203040303060105030505050203070205060105000407040102040502040502000104000104020601050405070301040402000606000101050701020400000402030107030300030304000203010103060501060204010300030601020202050605050207010204040701050007030202070700000106040303070406060606040501040702040102030203060502030204030605060102000206060506020307020301070707040606070302050206020500010706020406000705030201030207000305020701010401020202060407060703060004060006010201060207050200030705060406000700000400000403010707060500000306000402010202000600070403070203050505060201050304000607030305040503000702050207010700040301030401060007040204070707070401000501070605030602040504020000010403020000030100040306070707010606050605020305010704000405070701020303010604050002050705010505000101000603020202050101010607010203020000030106020105010702050503010400010404060605020707020001020701010206030006010002020504010401060007060603000601050506040500070304010702070401000006050603070202010105040000040301010707000007050400010101070402070706050103040106070400070204030100020100060007050304030104060707000601010407030300040005000406030407", (char*)(local_7020 + 15058));
    hex2bin("070307030400000605060705020101020706020403050605070105060205030005000206000502010600020203020500060200000300050102050600070004060506050500010005030300000301040700040605040603070401030602000006050600040706060405020300040402010501050100010306050201010306070703050305060400070506050506030700040503050104030505040706040104070107060502010004050402010606010306030602070205070700050003050600060103060305000501040405060604050306050504040205000600060401030704040605030605000706040703060504030003060105040506060400040406000307060602020000000604000501010500010004050005000706020205000504050405010007060001040102010104040003060301060503000006020500040607010506040405070701070106060206000003070400020207040506070300050101040304050605020107000304040703060405040706060106040007030003040602030201050106000106070505040402030405030505040004040103000406050703010100040405040504040305040404010403000406050506000604060000030305060002050006020300000602070503070600050000020004020102010504040601060105070605010306010706060605070404060606060307000001010404060507050503030502070404050500040000060601030105050404040402050703040506030606040400040705050502030305060206020607000004040700000501030101000002040006010100070504050504020400030607020404070106060404070707010207040403030000030107020204060704060100040302030202040405020406010101030000010207060106020501000307010503060704050005020306020100060505050307010002050500020606040604010402000603050504020101040004000706050605010606040306040105000705040000060307000405010604070500070306030005050304040700050006020506020104060000060406050705070006070206000104030003030703000700000005060702040605040107040405050005050202000300060504050505000103000404010606020600050206060202040006000403050203040005040006010201050200040005070100030507070104060400030700000607050007040404070400050700000300060401060607040400000001050002030401010602050706050502060206060005030704000506010005020305010200050703040007010204000005000105000102010203030405040606030007060105060502060303020304010606060004010006030504040502050500040404070603030306000500000005", (char*)(local_7020 + 7530));
   // hex2bin("040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404", (char*)(local_7020 + 11218));
    hex2bin("000607050107030606040405020406070206060306040007050102060500020703010201050401020105050304020404050204030004030304000500000002040201050406060707030605040101050405000102000203040403000603020405040206050006050706040407000706070601040105050700000300060407040506070406060304040506000604030400010601010503060100060101060607030600020607030206000605040400040001000004060505030000050604050707050500030106000205010005020006000203020407040005000301050704030400060306040504040607000303070600060405060104060700000404060606030203050702020600000002020006000107050604060600030003050104060506030005040600030300050604010306060405010000020501060002070406020106040103000400010503060601020300030405030701040400040703030606050400050400040306000507050505050607010002070606020501030306020603040207050100000700040102020301010506020501040506010605000105040103000501000502020600060406010505070106020602040602040105020405000305020005020402050500040006000505040002050006000204010702040006070606030104060407000401030506000202000205000500000207060505040600020403070005010004060304030501070403060400030100030100050606070400030704040006010307000604010302020206050703010303070103060601020601050405030202040404020002070103040706060001030601040604040004010603070104000101050403020200050400060507000205020604060605030706010000000602050106060503010306050202060700070206060202020504040604060603070307000601070302060002040707010603060007040104030601040502010504020402060704070105000301030005010307000404010407070002050306020305060207020405030400050500030006070005060402010005020600070500020106000405050502040703040002020405040406070402050404000602070700010502000500020200020505010000020107050207060602060306020304000403030705030105060601030407040502060403060505050304040401000005060000070503020100050402000002030305040200050607010503020501050205040306010504070206000304040306020700050104040001030400000403060103050706050604020606060700020401010007070502010600020405040507030205000703040104050504070000040106050401040201010501070004060005060405000503060601060000070701030003030501040502060703", (char*)(local_7020 + 3582));
    hex2bin("040500070405060105060400000500050601010001060506050406020100020104000006040502060705030502040505050506050506040004030403060600030200050002040407060402000607070500000203070206000704030102060405060502050407010604000607040204010400010204000600060504040505050503000404000300030204040303030003000706050105040704050401000506050502050500000707020606030000050604070105030407030404010406030103000101010006010506060205050602050006000007020704010205060407010704040500040003020206000001000406020401070703040400030305000200050406000702060107040001040400040006060207060102070205060100000704000503060004000007000700030502030102030500060506040600050000030500070000020202010303040007010305060502010607000404060007000605050004010207060006050405000603060206000200040207000701000404020606070507060004030206040700020502070406020003050202070407050501050005010400000103050200030206030401020201020304030600070001020403060101010506000704060605050006040406010005070503040604040107030000070602000004040200060201050605010106050504030304060001000106060200050605060307000303050400040705030706000701020300040606050600050206060100010404060504050403060100030507060005060505070305030606060504070300040602070501020602050407060006000500000305070401050302070703020206020304060507050403020703050600050105050204040200000506010507050504030102010306020004030404050404070504050200030604070200060207040003070004020603070100040302060600060207010200060105040203040107050100030504050602000500030306010402070507030504020503030604050204000401060205000100050103000204000207000202050602040204050107070405060101040300020205030400060206050106050501070500060103000006030500020505000404070003040505050606060400010507040100010703050405070600010404020604070406040601010603070500000203010204020305000103000602030605030203050504000002000001060407010403060303040605020205070007060701020000060600050302030302070705030501050200050200060600010004040000010304030606070003070403070605070307020700000104040405040202070605000202060705060004000007020306040406070602040406010403060406050101070200030105000606020605050605", (char*)(local_7020 + 1490));
    int ioffs = 0x3191 % 1026;
    int joffs = 0x3191 % 1026;
    coffset += (1 * 16);
    cjump = 0x60f;
    byte* cinput = local_7020 + 19942;
    byte* dinput = local_7020 + 15058;
    byte bcarry=0;
    byte gcarry = 0;
    byte err[1026];
    err[0] = 0;
    err[1] = 0;
    for (int i = 0; i < 1024; i++)
    {
        err[i+2] = __metaSafetable[i];
    }
    for (int i = 0; i < 1026; i++)
    {
           uint  uVar1 = (uint)(byte)(DAT_1809cde30)[trythis[i ] << 0xb | (err[i ] << 8) | bcarry | err[i ]];
           bcarry = uVar1 & 0xf8;
           dinput[ioffs] =  uVar1 & 7;
           int  vl = 0;
           uint  uVar2 = (uint)(byte)(DAT_1809cde30)[trythat[i] << 0xb | (vl << 8) | gcarry | vl];
           gcarry = uVar2 & 0xf8;
           cinput[ioffs] =uVar2 & 7;
           ioffs = (ioffs + 0x81df) % 1026;
    }
    while (true)
    {
        ert = (coffset - DAT_1812f29b0) / 16;
     
        switch (cjump)
        {
        case 0x958:
        {
            //LAB_18016c3f2
            uint r13d = *(uint*)(&coffset[0]);
            uint r15d = *(short*)(&coffset[8]);
            uint ebx = *(short*)(&coffset[10]);
            cjump = *(short*)(&coffset[14]);
            byte* rcx = local_7020 + ebx;
            uint edi = 0x1ff;
            uint r12d = (r13d >> 0x12);
            *(short*)rcx = (r12d)&0x1ff;
            //memset lv890 0x800, 0xaa
            uint esi = r12d & 0x1ff;
            if (esi != 0)
            {
                lc38 = ebx;
                uint r9d = (r13d & 0x1ff);
                uint r8d = ((r13d >> 0x9) & 0x1ff);
                int fill = 0;
                int ffd = 0;
                if (r8d + r9d > esi)
                {
                    fill = esi - r9d;
                }
                else
                {
                    fill = r8d;
                    ffd = esi - r8d - (r13d & 0x1ff);
                }
                //zeros,copy, zeros? 
                r13d >>= 0x1b;
                r13d &= 7;
                byte* r15 = local_7020  + r15d + 2;
                ebx = 0;
                uint r10d = 0x3191 % r8d;
                uint edi = r9d - 1;
                uint ebp = 0x3191;
                //LAB_18016c495
                for(ebx=0;ebx!=esi;ebx++)
                {
                    ebp = ebp % esi;
                    if (ebx <= r9d - 1)
                    {
                        lv890[ebp] = 0;
                    } 
                    //LAB_18016c495
                    if (ebx == r9d -1)
                    {
                        lv890[ebp] = r13d & 0xff;
                    }
                    //LAB_18016c4be
                    if (ebx > r9d - 1) 
                    {
                        if (ebx <=r8d + r9d)
                        {
                            
                            lv890[ebp] = r15[r10d];
                          //  if (ert >= 21049 &&ert<= 21049)  lv890[ebp] = 4; 
                            r10d = (r10d + 0x81df )% r8d;
                        }
                        else
                        {
                            lv890[ebp] = 0;
                        }

                    }
                    ebp += 0x81df;
                };
                if (esi != 0)
                {
                    rcx = lc38 + local_6ff0;
                  //  r12d &= 0x1ff;
                    memcpy(rcx, lv890, esi);
                }

            }
            coffset += 16;
        }; break;
        case 0x812: //18016C538
        {
            ulonglong r15 = *(ulonglong*)(&coffset[0]);
            byte* rdi = local_7020;
            byte* rcx = rdi + *(short*)(&coffset[8]);
            uint rbp = *(short*)(&coffset[10]);

            byte* r13 = rdi + rbp;
            uint rbx = *(short*)(&coffset[12]);
            byte* rax = rdi + rbx;
            byte* lc30 = rax;
            cjump = *(short*)(&coffset[14]);
            uint lc28 = r15 & 0x3fffff;
            ulonglong r12 = (r15 >> 0x24);
            uint esi = r12 & 0x3fff;
            lc38 = esi;//todo: CHECK
            r15 >>= 0x32;
            uint lc60 = *(short*)rcx; //r14=rcx
            uint r13d = *(short*)r13;
            ulonglong lc48 = r15;
            r15 += esi; //lc38
            *(short*)lc30 = (short)r15;
            byte* r8 = rdi + rbp + 2;
            byte* r9 = rdi + rbx + 2;
            uint ecx = 0x3191 % r15;
            uint ebx = 0x3191;
            uint ebp = 0x3191 % r13d;
            uint edi = 0;
             // process esi length through table from (rcx[ebx+2],r8[ebp]) to r9[ecx] lengths r10d, r13d, r15
            //process 0,r8[ebp] of length lc48 into r9[ecx]
         
            if (esi != 0)
            {
                uint ls30 = esi;
                esi = 0;
               // uint r11d = 0x81df;
                uint r10d = lc60;
                do
                {
                    ebx = ebx % r10d;
                    byte  ax = rcx[ebx + 2];
                    edi &= 0xf8;
                    edi = edi ^ (uint)ax;
                    //eax=ebp
                    ulonglong rax = (r8[ebp] << 8) | edi;
                    // ulonglong rdx = lc28 + esi;
                    ulonglong edx = DAT_180a25040[lc28 + esi];
                    edx <<= 0xb;
                    edx ^= rax;
                    edi = DAT_1809cde30[edx];
                    ax = edi & 7;
                    r9[ecx] = ax;
                    ebx += 0x81df;
                    ebp += 0x81df; 
                    ecx += 0x81df;
                    esi++;
                    ecx %= r15;
                    ebp %= r13d;
                } while (esi != lc38);

            }
            if (lc48 != 0)
            {
                r12 &= 0x3fff;
                ebx = (uint)r15;
                //r11=DAT_1809cde30

                do
                {
                    edi &= 0xf8;
                    ulonglong r10 = ((ulonglong)r8[ebp]) << 8;
                    r10 |= edi;
                    ebp += 0x81df;
                    r10 ^= (DAT_180a25040[lc28 + r12] << 0xb);
                    edi = DAT_1809cde30[r10];
                    byte ax = edi & 7;
                    r9[ecx] = ax;
                   // if (ert == 26763) r9[ecx] = 4;
                    ebp %= r13d;
                    ecx = (ecx + 0x81df) % r15;
                    r12++;

                } while (r12 < ebx);
            }
            coffset += 16;
        }; break;
        case 0x60f:
        {
            ulonglong rbx = *(ulonglong*)(&coffset[0]);
            uint esi = *(short*)(&coffset[8]);
            byte* rbp = local_7020;
            byte* rcx = rbp + esi;
            uint lc28 = *(short*)(&coffset[10]);
            byte* lc48 = rbp + lc28;
            cjump = *(short*)(&coffset[14]);
            uint r13d = rbx & 0x3fffff;
            ulonglong r12 = (rbx >> 0x16);
            ulonglong rdi = (rbx >> 0x24) & 0x3fff;
            //eax=0x3fff
            rbx >>= 0x32;
            uint r15d = *(short*)rcx;
            ulonglong lc38 = rbx;
            ulonglong r14d = rdi + rbx;
            *(short*)lc48 = (short)r14d;
            //r11=rdi
            //r9d=0x3fff
            uint edi = 0;
            uint ebx = 0x3191 % r15d;
            byte* r10 = rbp + esi + 2;
            uint r9d = 0x3fff & r12;
            // process r10[ebx],0 of length r9d  (offset r13d) in 2-byte chunks
            // process r10[ebx],0 of len rdi into r8[ecx] (use 2-byte) 
            // process r10[ebx],0 of lc38 (in different order?)  into r8[ecx]
            if (r9d != 0)
            {
                uint ecx = r9d;
                edi = 0;
                esi = 0;
                //r8=DAT_180a25040
                //rbp=DAT_180b2f040
                do
                {
                    ulonglong ax = r10[ebx];
                    ebx += 0x81df;
                    edi &= 0xff8;
                    edi ^= (uint)ax;
                    ax = DAT_180a25040[r13d + esi] << 0xc;
                    ax |= edi;
                    edi = *(short*)(&DAT_180b2f040[ax * 2]);
                    esi++;
                    ebx %= r15d;
                } while (ecx != esi);

            }
            //rax= local_7020
            //rsi -offset
            byte* r8 = local_7020 + lc28 + 2;
            uint ecx = 0x3191 % r14d;
            r9d += (uint)rdi;
            uint ebp = r9d;
            if (rdi != 0)
            {
                //  lc28 = r9d;
                r12 &= 0x3fff;
                //r9d=0x81df
                //r11= DAT_180b2f040 
                do
                {
                    ulonglong si = r10[ebx];
                    ebx += 0x81df;
                    ebx %= r15d;
                    edi &= 0xff8;
                    edi ^= si;
                    ulonglong rax = ((ulonglong)DAT_180a25040[r12 + r13d]) << 0xc;
                    edi |= rax;
                    edi = *(short*)(&DAT_180b2f040[edi * 2]);
                    //rsi=DAT_180a25040
                    r8[ecx] = (edi & 7);
                    //if (ert == 26764)  r8[ecx] = 4;
                    // 26764 does nothing
                    ecx += 0x81df;
                    ecx %= r14d;
                    r12++;
                } while (r12 < ebp);

            }
            if (lc38 != 0)
            {
                ebx = 0x1354f;
                r9d += (uint)lc38;
                //esi=0x81df
                //r12=DAT_180a25040
                //r11=DAT_180b2f040
                do
                {
                    ebx %= r15d;
                    ulonglong ax = r10[ebx];
                    ax ^= edi;
                    ebx += 0x81df;
                    ulonglong edx = DAT_180a25040[r13d + ebp] << 0xc;
                    edx ^= ax;
                    edi = *(short*)(&DAT_180b2f040[edx * 2]);
                    r8[ecx] = (edi & 7);
                    ecx += 0x81df;
                    ecx %= r14d;
                    ebp++;
                } while (ebp < r9d);
            }
            coffset += 16;
        }; break;
        case 0x3f9:
        {
            ulonglong r13 = *(ulonglong*)(&coffset[0]);
            uint r15d = *(short*)(&coffset[8]);
            uint ebx = *(short*)(&coffset[10]);
            //rax=local_7020
            byte* rcx = local_7020 + ebx;
            cjump = *(short*)(&coffset[14]);
            // edi=0xfffff
            ulonglong r12 = r13 >> 0x28;
            *(short*)rcx = (short)(r12 & 0xfffff);
            uint esi = r12 & 0xfffff;
            ulonglong r8 = (r13 >> 0x14) & 0xfffff;
            if (esi != 0)
            {
                lc38 = ebx;
                uint r9d = r13 & 0xfffff;
                r13 >>= 0x3c;
                r13 &= 7;
                byte* r15 = local_6fe8 + r15d;
                uint ecx = 0x3191;
                uint edi = 0;
                uint r10d = 0x3191 % r8;
                ebx = r9d - 1;
               // r9d = -r9d;
                do
                {
                    ecx = ecx % esi;
                    if (edi < r9d - 1)
                    {
                        lv90[ecx] = 0;
                    }
                    if (edi == r9d -1)
                    {
                        lv90[ecx] = (byte)r13;
                    }
                    if (edi > r9d - 1)
                    {
                        if (edi < r8 + r9d)
                        {
                            lv90[ecx] = r15[r10d];
                            r10d += 0x81df;
                            r10d %= r8;
                        }
                        else
                        {
                            lv90[ecx] = 0;
                        }

                    }
                    if (ert == 26762)   lv90[ecx] = 4;
                    //if (ert == 19)   lv90[ecx] = 4;
                    ecx += 0x81df;
                    edi++;
                } while (esi != edi);

                if (esi != 0)
                {
                   // r12 &= 0xfffff;
                    memcpy(local_6ff0 + lc38, lv90, esi);
                    //if (ert == 26762)
                     //   memcpy(local_6ff0 + 7530, lv90, esi);
                }

            }
            coffset += 16;
        }; break;
        case 0x2b4: // LAB_ 18016CA96
        {
            ulonglong r12 = *(ulonglong*)(&coffset[0]);
            uint lv50= *(short*)(&coffset[8]); //eax
            byte* rcx = local_7020 + lv50;
            uint ebp= *(short*)(&coffset[10]);
            byte* rdi = local_7020 + ebp;
            uint lv48 = *(short*)(&coffset[12]); //eax
            byte* rrax = local_7020 + lv48; //0x28

            cjump = *(short*)(&coffset[14]);
            uint r15d = r12 & 0x3fffff;
            ulonglong r14 = (r12 >> 0x16);
            ulonglong rbx= (r12 >> 0x24)& 0x3fff;
            //eax=0x3fff;
            r12 >>= 0x32;
            uint r13d = *(short*)rcx;
            uint edi = *(short*)rdi; //rcx=rdi
            ulonglong lc68 = r12;
            ulonglong lc58 = rbx;
            *(short*)rrax=(short)(rbx + r12);
            uint lc28 =(uint)( rbx + r12);
            uint r9d = edi;
            uint r8d = r13d;
            edi = 0;
            uint ebx = 0x3191 % r9d;
            uint ecx = 0x3191 % r13d;
            byte* r13 = local_7020 + lv50 + 2;
            //r12=0x3fff
            byte* rsi = local_7020 + ebp + 2;
            r12 = 0x3fff & r14;
            byte * lc50 = r13;
            ulonglong lc38 = r15d;
            uint lc30 = r8d;
            //process r13[ecx],rsi[ebx] of length r12 to ... nothing? 
            // process r13,rsi of length lc58 to r15
            //process ...0,0 of length  l68 (from r13d length) to rax48=r15
            if (r12 != 0)
            {
                //r11=rsi;
                uint esi = 0;
                uint r10d = (uint)r12;
              //  ebp = 0x81df;
                edi = 0;
                do
                {
                    ulonglong ax = r13[ecx];
                    ecx+= 0x81df;
                    edi &= 0xf8;
                    edi ^= ax;
                    ax = (rsi[ebx]<<0x8)|edi;
                    ebx+= 0x81df;
                    ulonglong rdx=DAT_180a25040[r15d+esi]<<0xb;
                    rdx |= ax;
                    edi = DAT_1809cde30[rdx];
                    esi++;
                    ebx %= r9d;
                    ecx %= r8d;
                } while (r10d!=esi);
            }      
           //rax= local_7020
           //rdx= lv48
            byte* rax48 = local_7020 + lv48 + 2;
            //eax=0x3191
            ebp = 0x3191 % lc28;
            //rax=lc58
            r12 += lc58;
            r13d = (uint)r12;
            if (lc58 != 0)
            {
                lc58 = r12;
                r14 &= 0x3fff;
                //r11d=0x81df
                r8d = lc28;
               byte * r10 = lc50;
               byte* r15 = rax48;
               do
               {
                   r12 = r10[ecx];
                   ecx += 0x81df;
                   ecx %= lc30;
                   edi &= 0xf8;
                   edi |= r12;
                   ulonglong esi = rsi[ebx];
                   esi <<= 0x8;
                   esi |= edi;
                   ebx += 0x81df;
                   ebx %= r9d;
                   //rax=lc38+r14
                   ulonglong ax = DAT_180a25040[lc38 + r14] << 0xb;
                   ax ^= esi;
                   edi=DAT_1809cde30[ax];
                   r15[ebp] = edi & 7;
                  // if (ert == 26760) r15[ebp] = 4;
                   //    18016cca5 4c 89 e6        MOV        RSI, R12    
                   r14++;
                   ebp += 0x81df;
                   ebp = ebp % r8d;
               } while (r14<r13d);
               r12 = lc58;
              // r15 = lc38;
            }
           // rcx = rax48;
           //   18016cced 8b 74 24 28     MOV        ESI, dword ptr[RSP + 0x28]
           uint  esi = lc28; 
           if (lc68!=0) //rax
           {
               r12 += lc68;
               //r9=DAT_180a25040
               // rbx=DAT_1809cde30
                   do
                   {
                       edi &= 0xf8;
                       ulonglong ax = DAT_180a25040[lc38 + r13d];
                       ax <<= 0xb;
                       ax |= edi;
                       edi = DAT_1809cde30[ax];
                       rax48[ebp] = edi & 7;
                       ebp += 0x81df;
                       ebp %= esi;
                       r13d++;
                   } while (r13d < r12);
            }
           coffset += 16;
        }; break;
        case 0: //LAB_18016cd4a
        {
            byte* rcx = local_7020+ 0xdfc;
            Divshuffler_18011411d(rcx, 0x404, param_3);
            rcx = local_7020 + 0x5d0;
            Divshuffler_18011411d(rcx, 0x404, param_4);
            rcx = local_7020 + 0x3f10;
            Divshuffler_18011411d(rcx, 0x410, param_5);
            //0x7088=param5
            // RSI=local_7020
            rcx = local_7020 + 0x1434;
            Divshuffler_18011411d(rcx, 0x410, param_6);
            return;
        }
        }

    }
}


void Crazery_18016c0bb(char* param_1, byte * param_2, byte * param_3, byte * param_4,
        byte * param_5)

{
    longlong lVar2;
    byte salt[82];
    FillRandom_1801a741c(salt, 0x52);
    lVar2 = 0;
    do {
        salt[lVar2] = salt[lVar2] & 7;
        lVar2 = lVar2 + 1;
    } while (lVar2 != 0x52);
    salt[2] = 0;
    Crazery_18016c170(param_1, (char*)salt, param_2, param_3, param_4, param_5);
    return;
}

void Shufflemul_1801a34a5(byte* param_1, byte* param_2, byte* param_3, int* param_4)

{
    byte* pbVar1;
    byte bVar2;
    uint uVar3;
    longlong lVar4;
    int* piVar5;
    longlong lVar6;
    longlong* plVar7;
    int iVar8;
    int iVar9;
    ulonglong uVar10;
    ulonglong uVar11;
    longlong lVar12;
    uint uVar13;
    undefined8* puVar14;
    ulonglong uVar15;
    ulonglong uVar16;
    ulonglong uVar17;
    uint uVar18;
    bool bVar19;
    undefined8 uVar23;

    longlong local_55d0;
    ulonglong local_55c8;
    ulonglong local_55c0;
    ulonglong local_55b8;
    longlong local_55b0;
    ulonglong local_55a8;
    byte* local_55a0;
    int* output_holder;
    uint local_5584;
    uint local_5580[90];
    int local_5410[90];
    int local_52a0[90];
    byte local_5130[1312];
    uint local_4c10[188];
    int local_4920[96];
    int local_47a0[96];
    byte local_4620[372];
    byte local_44a0[18];
    byte local_4480[18];
    longlong local_43d0[327];
    byte local_39a0[744];
    longlong local_36b0[327];
    //undefined2 local_2c70;
    int local_2250[744];
    longlong  local_2c80[327];
   byte  local_16b0[32];

    longlong local_1690[2608/8];
  
    int local_c60[742];/// 740.5?
    byte local_d0[36];
    //undefined8 uStack72;
    longlong local_4460[0x88/8];

    output_holder = param_4;
    Maybe_MEMSET_180512a50((char*)local_52a0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_5410, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_5580, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x168);
    lVar4 = 0;
    do {
        local_2250[lVar4] = *(int*)((longlong)DAT_18091bb90 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] =
            local_2250[lVar4] +
            *(int*)(param_1 + lVar4 * 4) *
            *(int*)((longlong)DAT_18091bbb0 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] =
            local_2250[lVar4] +
            *(int*)(param_2 + lVar4 * 4) *
            *(int*)((longlong)DAT_18091bbd0 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    iVar9 = 0x1458af01;
    lVar4 = 0;
    do {
        iVar8 = iVar9 * -0x77fa654f + local_2250[lVar4];
        uVar13 = iVar8 * 0x5d912e6d + 0x842fe763;
        local_c60[0]=uVar13;
        lVar6 = 0;
        do {
            uVar13 = (uVar13 >> 4) + (INT_18091bbf0 [(uVar13 & 0xf) ]);
            local_c60[lVar6 + 1] = uVar13;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 8);
        uVar10 = (ulonglong)((int)lVar4 * 4 & 0x1c);
        iVar9 = local_c60[7] * 0x199500f5 + local_c60[8] * 0x66aff0b0 + -0x69600e1;
        local_52a0[lVar4] =
            (iVar8 * 0x4492a027 + local_c60[7] * -0x30000000 + 0x6a7bcd8d) *
            *(int*)((longlong)DAT_18091bc30 + uVar10) + *(int*)((longlong)DAT_18091bc50 + uVar10);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    local_55a0 = param_2;
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x168);
    lVar4 = 0;
    do {
        local_2250[lVar4] = *(int*)((longlong)DAT_18091bc70 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] =
            local_2250[lVar4] +
            *(int*)(param_1 + lVar4 * 4) *
            *(int*)((longlong)DAT_18091bc90 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] =
            local_2250[lVar4] +
            *(int*)(param_3 + lVar4 * 4) *
            *(int*)((longlong)DAT_18091bcb0 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    iVar9 = 0x56922dd6;
    lVar4 = 0;
    do {
        iVar8 = iVar9 * -0x51c0e29d + local_2250[lVar4];
        uVar13 = iVar8 * 0x2b9e5e5f + 0xe2dd38b5;
        local_c60[0] =  uVar13;
        lVar6 = 0;
        do {
            uVar13 = (uVar13 >> 4) + *(int*)( DAT_18091bcd0 + (ulonglong)(uVar13 & 0xf) * 4);
            local_c60[lVar6 + 1] = uVar13;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 8);
        uVar10 = (ulonglong)((int)lVar4 * 4 & 0x1c);
        iVar9 = local_c60[7] * -0x2857fe6b + local_c60[8] * -0x7a801950 + 0x68e87261;
        local_5410[lVar4] =
            (iVar8 * -0x5d78ace9 + local_c60[7] * 0x70000000 + -0x3cad9d7f) *
            *(int*)((longlong)INT_18091bd10 + uVar10) + *(int*)((longlong)DAT_18091bd30 + uVar10);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_47a0, 0xaa, 0x174);
    Maybe_MEMSET_180512a50((char*)local_4920, 0xaa, 0x174);
    Maybe_MEMSET_180512a50((char*)local_4c10, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_5130, 0xaa, 0x518);
    Maybe_MEMSET_180512a50((char*)local_4620, 0xaa, 0x174);
    lVar4 = 0;
    do {
        *(undefined4*)(local_4620 + lVar4 * 4) =
            *(undefined4*)((longlong)DAT_18091cb70 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5d);
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4) =
            *(int*)(local_4620 + lVar4 * 4) +
            local_52a0[lVar4] * *(int*)((longlong)DAT_18091cb90 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4 + 0x168) =
            *(int*)(local_4620 + lVar4 * 4 + 0x168) + *(int*)((longlong)DAT_18091cbb8 + lVar4 * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 3);
    piVar5 = (int *) DAT_18091bd50;
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4) =
            *(int*)(local_4620 + lVar4 * 4) +
            *piVar5 * *(int*)((longlong)DAT_18091cbd0 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
        piVar5 = piVar5 + 1;
    } while (lVar4 != 0x5d);
    iVar9 = -0x555d1590;
    lVar4 = 0;
    do {
        iVar8 = iVar9 * 0x3f1b9b61 + *(int*)(local_4620 + lVar4 * 4);
        uVar13 = iVar8 * 0x16bc5943 + 0x7c715e6e;
        local_c60[0] = uVar13;
        lVar6 = 0;
        do {
            uVar13 = (uVar13 >> 4) + *(int*)(DAT_18091cbf0 + (ulonglong)(uVar13 & 0xf) * 4);
            local_c60[lVar6 + 1] = uVar13;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 8);
        uVar10 = (ulonglong)((int)lVar4 * 4 & 0x1c);
        iVar9 = local_c60[8] * 0x385c9b50 + local_c60[7] * -0x2385c9b5 + -0x3a122240;
        local_47a0[lVar4] =
            (iVar8 * -0x755b7ce3 + local_c60[7] * 0x10000000 + 0x3ebd3bdc) *
            *(int*)((longlong)DAT_18091cc30 + uVar10) + *(int*)((longlong)DAT_18091cc50 + uVar10);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5d);
    Maybe_MEMSET_180512a50((char*)local_4620, 0xaa, 0x174);
    lVar4 = 0;
    do {
        *(undefined4*)(local_4620 + lVar4 * 4) =
            *(undefined4*)((longlong)DAT_18091cc70 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5d);
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4) =
            *(int*)(local_4620 + lVar4 * 4) +
            local_5410[lVar4] * *(int*)((longlong)DAT_18091cc90 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4 + 0x168) =
            *(int*)(local_4620 + lVar4 * 4 + 0x168) + *(int*)((longlong)DAT_18091ccb8 + lVar4 * 4);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 3);
    piVar5 = (int *) DAT_18091bed0;
    lVar4 = 0;
    do {
        *(int*)(local_4620 + lVar4 * 4) =
            *(int*)(local_4620 + lVar4 * 4) +
            *piVar5 * *(int*)((longlong)DAT_18091ccd0 + (ulonglong)((uint)lVar4 & 7) * 4);
        lVar4 = lVar4 + 1;
        piVar5 = piVar5 + 1;
    } while (lVar4 != 0x5d);
    iVar9 = -0x7fa3bc76;
    lVar4 = 0;
    do {
        iVar8 = iVar9 * 0x5895f28b + *(int*)(local_4620 + lVar4 * 4);
        uVar13 = iVar8 * -0x36365ea3 + 0xc5085d73;
        local_c60[0] = uVar13;
        lVar6 = 0;
        do {
            uVar13 = (uVar13 >> 4) + *(int*)(DAT_18091ccf0 + (ulonglong)(uVar13 & 0xf) * 4);
            local_c60[lVar6 + 1] = uVar13;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 8);
        uVar10 = (ulonglong)((int)lVar4 * 4 & 0x1c);
        iVar9 = local_c60[8] * 0x6bdc7810 + local_c60[7] * -0x56bdc781 + -0x67e7ea28;
        local_4920[lVar4] =
            (iVar8 * 0x384f7a07 + local_c60[7] * -0x30000000 + 0x4226abb5) *
            *(int*)((longlong)DAT_18091cd30 + uVar10) + *(int*)((longlong) DAT_18091cd50 + uVar10);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5d);
    Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0x5d0);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x5d0);
    Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_36b0, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_43d0, 0xaa, 0x2e8);
    Ya_Carry_1801a5b14(local_47a0, 0, local_2c80);
    SetOthConstCarry_1801a5bb6(0, local_36b0);
    local_1690[0] = local_2c80[0];
    longlong rbp= local_2c80[0];
    local_43d0[0] = local_36b0[0]; 
    lVar6 = 1;
    lVar4 = 8;
    do {
        Ya_Carry_1801a5b14(local_47a0, (uint)lVar6, &local_2c80[lVar4/8]);
        rbp = rbp + local_2c80[lVar6];
        local_1690 [lVar6] = rbp;
        lVar6 = lVar6 + 1;
        lVar4 = lVar4 + 8;
    } while (lVar6 != 0x5d);
    lVar4 = 1;
    lVar6 = 8;
    rbp= local_36b0[0];
    do {
        SetOthConstCarry_1801a5bb6((uint)lVar4, &local_36b0[lVar4]);
        rbp = rbp+ (local_36b0[lVar4]);
        local_43d0[lVar4] = rbp;
        lVar4 = lVar4 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar4 != 0x5d);
    uVar10 = 0;
    do {
        uVar16 = 0x5c;
        if (uVar10 < 0x5c) {
            uVar16 = uVar10;
        }
        uVar13 = (uint)uVar10;
        uVar11 = (ulonglong)(uVar13 - 0x5c);
        if (uVar13 < 0x5c) {
            uVar11 = 0;
        }
        lVar4 = 0x7e6cbe2787bcdfb4;
        uVar18 = (uint)uVar16;
        uVar3 = (uint)uVar11;
        if (uVar3 <= uVar18) {
            uVar15 = uVar10 - uVar11;
            lVar4 = 0;
            do {
                lVar4 = lVar4 + (local_36b0 [uVar15 & 0xffffffff]) *
                    (local_2c80[uVar11]);
                uVar11 = uVar11 + 1;
                uVar15 = uVar15 - 1;
            } while (uVar16 + 1 != uVar11);
            lVar6 =local_1690 [uVar16 ];
            if (0x5c < uVar10) {
                lVar6 = lVar6 - (local_1690 [ (ulonglong)(uVar3 - 1) ]);
            }
            lVar12 = (local_43d0 [ (ulonglong)(uVar13 - uVar3) ]);
            if (0x5c < uVar10) {
                lVar12 = lVar12 - (local_43d0 [ (ulonglong)(~uVar18 + uVar13) ]);
            }
            lVar4 = (ulonglong)((uVar18 - uVar3) + 1) * -0x1ebfa780edcfe087 + 0x7e6cbe2787bcdfb4 +
                lVar4 * 0x2f670f8d759334b5 + lVar6 * -0x67207758c1601e29 +
                lVar12 * -0x2868d58b5daf87c5;
        }
        *(longlong*)(local_c60 + uVar10 * 2) = lVar4 * 0x6fc0b89f1de69639 + 0x251801dd91588dbc;
        uVar10 = uVar10 + 1;
    } while (uVar10 != 0xba);
    Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_36b0, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_43d0, 0xaa, 0x2e8);
    SettCarry_1801a5c63(local_4920, 0, (longlong*)local_2c80);
    SetCarryFromConst_1801a5d05(0, (longlong*)local_36b0);
    local_1690[0] = local_2c80[0];
    local_43d0[0] = local_36b0[0];
    rbp = local_1690[0];
    lVar6 = 1;
    lVar4 = 8;
    do {
        SettCarry_1801a5c63(local_4920, (int)lVar6, (&local_2c80[lVar6]));
        rbp = rbp + (local_2c80[lVar6]);
        local_1690[lVar6 ] = rbp;
        lVar6 = lVar6 + 1;
        lVar4 = lVar4 + 8;
    } while (lVar6 != 0x5d);
    lVar4 = 1;
    lVar6 = 8;
    rbp=local_36b0[0];
    do {
        SetCarryFromConst_1801a5d05((int)lVar4, (&local_36b0[lVar4]));
        rbp = rbp + (local_36b0[lVar4]);
        (local_43d0 [lVar4 ]) = rbp;
        lVar4 = lVar4 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar4 != 0x5d);
    uVar10 = 0;
    do {
        uVar16 = 0x5c;
        if (uVar10 < 0x5c) {
            uVar16 = uVar10;
        }
        uVar13 = (uint)uVar10;
        uVar11 = (ulonglong)(uVar13 - 0x5c);
        if (uVar13 < 0x5c) {
            uVar11 = 0;
        }
        lVar4 = -0xe9dcbfa7538eaa5;
        uVar18 = (uint)uVar16;
        uVar3 = (uint)uVar11;
        if (uVar3 <= uVar18) {
            uVar15 = uVar10 - uVar11;
            lVar4 = 0;
            do {
                lVar4 = lVar4 + (local_36b0[uVar15 & 0xffffffff]) *
                    local_2c80 [uVar11 ];
                uVar11 = uVar11 + 1;
                uVar15 = uVar15 - 1;
            } while (uVar16 + 1 != uVar11);
            lVar6 = local_1690 [uVar16 ];
            if (0x5c < uVar10) {
                lVar6 = lVar6 -(local_1690 [ (ulonglong)(uVar3 - 1) ]);
            }
            lVar12 = (local_43d0 [ (ulonglong)(uVar13 - uVar3) ]);
            if (0x5c < uVar10) {
                lVar12 = lVar12 - (local_43d0 [ (ulonglong)(~uVar18 + uVar13) ]);
            }
            lVar4 = (ulonglong)((uVar18 - uVar3) + 1) * 0x1f4298908c80d230 + -0xe9dcbfa7538eaa5 +
                lVar4 * -0x24cdab95e3f1a3ef + lVar6 * 0x1496c87473103290 +
                lVar12 * -0x670772f7f9af11e5;
        }
        *(longlong*)(local_2250 + uVar10 * 2) = lVar4 * -0x76343cdbf368f121 + 0x60b79979d0f6f57e;
        uVar10 = uVar10 + 1;
    } while (uVar10 != 0xba);
    lVar4 = 0x5349853cbcad92d4;
    lVar6 = 0;
    do { 

        lVar12 = *(longlong*)(local_2250 + lVar6 * 2) * -0x5ccb3dd541ceda45 +
            *(longlong*)(local_c60 + lVar6 * 2) * -0x4d5e5b955ecdff9f + lVar4 * 0x3107b00dc17db23
            + 0x25c123dddfc86ef8;
        Maybe_MEMSET_180512a50(local_4460, 0xaa, 0x88);
        uVar10 = lVar12 * 0x48466dc5e7b834b5 + 0xc72c9f43cacdd1bd;
        local_4460[0] =  uVar10;
        lVar4 = 0;
        do {
            uVar10 = (uVar10 >> 4) + *(longlong*)(DAT_18091d070 + (ulonglong)((uint)uVar10 & 0xf) * 8);
            local_4460[lVar4+1] = uVar10;
            lVar4 = lVar4 + 1;
        } while (lVar4 != 0x10);
        uVar10 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        lVar4 = local_4460[16] * 0x6cf1bc1000000000 + local_4460[7] * 0x75dea28f5930e43f + -0x27684209495d9276;
        local_4c10[lVar6] =
            ((int)local_4460[7] * -0x30000000 + (int)lVar12 * -0x5aa6f621 + -0x267a4efd) *
            *(int*)((longlong)DAT_18091d0f0 + uVar10) + *(int*)((longlong)DAT_18091d110  + uVar10);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0xba);
    Maybe_MEMSET_180512a50((char*)local_4620, 0xaa, 0x174);
    Maybe_MEMSET_180512a50((char*)local_39a0, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_43d0, 0xaa, 0xa2e);
    Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0x5d0);
    Maybe_MEMSET_180512a50((char*)local_36b0, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x5d8);
    Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x2f0);

    lVar4 = 0;
    local_2250[0] = 0;
    local_1690[0] = 0;
    lVar6 = 0;
    do {
        uVar10 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar16 = (ulonglong)
            ((local_4c10[lVar6] * *(int*)((longlong)DAT_18091d130 + uVar10) +
                *(int*)((longlong)DAT_18091d150 + uVar10)) * -0x5c07d979 + 0xc988a412);
        uVar10 = uVar16 * 0x26346c3308ac78eb + 0xbb4a709d8b68ae4b;
        iVar9 = 8;
        do {
            uVar10 = (uVar10 >> 4) + (QWORD_18091d170)[(uint)uVar10 & 0xf];
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar12 = uVar10 * 0x5422f29100000000 + uVar16 * -0xc54d96e1f34a31b + 0x590813f116cb9a94;
        *(longlong*)(local_c60 + lVar6 * 2) = lVar12;
        lVar4 = lVar4 + lVar12;
        *(longlong*)(local_2250 + lVar6 * 2 + 2) = lVar4;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0xba);
    lVar4 = 0;
    lVar6 = 0;
    do {
        uVar10 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar10 = (ulonglong)
            (((INT_18091c4d0)[lVar6] * *(int*)((longlong)DAT_18091d1f0 + uVar10) +
                *(int*)((longlong)DAT_18091d210 + uVar10)) * 0x4cde0a47 + 0x359545d2);
        uVar16 = uVar10 * -0x149c6494389c30b9 + 0x17105874b227ef08;
        iVar9 = 8;
        do {
            uVar16 = (uVar16 >> 4) +
                *(longlong*)((longlong) DAT_18091d230 + (ulonglong)((uint)uVar16 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar12 = uVar16 * 0x3ccc906100000000 + uVar10 * 0x373ed9c37e028619 + 0x53069b1417307c0d;
        local_36b0[lVar6] = lVar12;
        lVar4 = lVar4 + lVar12;
        *(longlong*)((longlong)local_1690 + lVar6 * 8 + 8) = lVar4;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5d);
    lVar4 = 0x72433dfef8d6b378;

    uVar10 = 0;
    do {
        plVar7 = (longlong*)local_c60;
        lVar6 = 0;
        uVar16 = uVar10;
        do {
            lVar6 = lVar6 +local_36b0 [uVar16 & 0xffffffff] * *plVar7;
            plVar7 = plVar7 + 1;
            bVar19 = uVar16 != 0;
            uVar16 = uVar16 - 1;
        } while (bVar19);
        uVar16 = uVar10 + 1;
        lVar6 = uVar16 * 0x64724e8c0ba65d6c + lVar4 + lVar6 * -0x799e708c4f992291 +
            *(longlong*)(local_2250 + uVar10 * 2 + 2) * 0x7cd0665b88774953 +
            (local_1690 [ uVar10  + 1]) * -0x48b74785a55c73a4;
        Maybe_MEMSET_180512a50(local_4460, 0xaa, 0x88);
        uVar11 = lVar6 * 0x6aef53526b07237b + 0xe6cffcc9ee70a5d7;
        local_4460[0] =uVar11;
        lVar4 = 0;
        do {
            uVar11 = (uVar11 >> 4) + *(longlong*)(DAT_18091d2b0 + (ulonglong)((uint)uVar11 & 0xf) * 8);
            local_4460[lVar4+1] = uVar11;
            lVar4 = lVar4 + 1;
        } while (lVar4 != 0x10);
        lVar4 = local_4460[16] * 0x2a4bc4d000000000 + local_4460[7] * 0x5d2b991d5d5b43b3 + 0x60f44b91bd67c5ab;
        uVar11 = (ulonglong)((int)uVar10 * 4 & 0x1c);
        *(int*)(local_4620 + uVar10 * 4) =
            ((int)local_4460[7] * -0x30000000 + (int)lVar6 * -0x78f1ff0f + -0x68f736c9) *
            *(int*)((longlong)DAT_18091d330 + uVar11) + *(int*)((longlong)DAT_18091d350 + uVar11);
        uVar10 = uVar16;
    } while (uVar16 != 0x5d);
    Maybe_MEMSET_180512a50((char*)local_36b0, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0x2e8);
    Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x2f0);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x2f0);
    lVar4 = 0;
    local_1690[0] = 0;
    local_2250[0] = 0;
    lVar6 = 0;
    do {
        uVar10 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar10 = (ulonglong)
            ((*(int*)((longlong) DAT_18091c350 + lVar6 * 4) *
                *(int*)((longlong) DAT_18091d370 + uVar10) +
                *(int*)((longlong) DAT_18091d390 + uVar10)) * 0x2aca8679 + 0x27374753);
        uVar16 = uVar10 * -0x14e95455a19556bf + 0xb58984dac95d2227;
        iVar9 = 8;
        do {
            uVar16 = (uVar16 >> 4) + *(longlong*)( DAT_18091d3b0 + (ulonglong)((uint)uVar16 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar12 = uVar16 * -0x49206f4b00000000 + uVar10 * -0x8fb6ad6663d3af5 + -0x634cefc90bf57cb3;
        local_36b0[lVar6] = lVar12;
        lVar4 = lVar4 + lVar12;
        local_1690 [lVar6 +1] = lVar4;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5d);
    lVar4 = 0;
    lVar6 = 0;
    do {
        uVar10 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar16 = (ulonglong)
            ((*(int*)(local_4620 + lVar6 * 4) * *(int*)((longlong)DAT_18091d430 + uVar10) +
                *(int*)((longlong)DAT_18091d450 + uVar10)) * -0x6e755531 + 0x41529b19);
        uVar10 = uVar16 * -0x51fd630514a69faf + 0x5e6d636cd423ffac;
        iVar9 = 8;
        do {
            uVar10 = (uVar10 >> 4) + *(longlong*)( DAT_18091d470 + (ulonglong)((uint)uVar10 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar12 = uVar10 * 0x489717a100000000 + uVar16 * -0x604b2ba8a2a3d9f1 + -0x5c0bf3bdafb5b61;
        local_2c80 [lVar6 ] = lVar12;
        lVar4 = lVar4 + lVar12;
        *(longlong*)(local_2250 + lVar6 * 2 + 2) = lVar4;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5d);
    lVar4 = 0x4640375e5bf33358;
    uVar10 = 0;
    do {
        uVar16 = 0x5c;
        if (uVar10 < 0x5c) {
            uVar16 = uVar10;
        }
        uVar13 = (uint)uVar10;
        uVar18 = uVar13 - 0x5c;
        if (uVar13 < 0x5c) {
            uVar18 = 0;
        }
        uVar3 = (uint)uVar16;
        if (uVar18 <= uVar3) {
            uVar17 = (ulonglong)uVar18;
            uVar15 = uVar10 - uVar17;
            lVar6 = 0;
            uVar11 = uVar17;
            do {
                lVar6 = lVar6 + local_2c80 [uVar15 & 0xffffffff] * //local_2c80 [64] is wrong
                   local_36b0 [ uVar11 ];
                uVar11 = uVar11 + 1;
                uVar15 = uVar15 - 1;
            } while (uVar16 + 1 != uVar11);
            lVar12 = *(longlong*)(local_2250 + (ulonglong)((uVar13 - uVar18) + 1) * 2);
            if (0x5c < uVar10) {
                lVar12 = lVar12 - *(longlong*)(local_2250 + (ulonglong)(uVar13 - uVar3) * 2);
            }
            lVar4 = (ulonglong)((uVar3 - uVar18) + 1) * -0xef38e48f7c89b58 + lVar4 +
                lVar6 * 0x2eeedd669313c37 +
                ((local_1690 [ uVar16 +1 ]) - (local_1690 [ uVar17 ]))
                * 0x7518c1f4a01bd1e8 + lVar12 * -0x695ae1212895f8c1;
        }
        Maybe_MEMSET_180512a50(local_4460, 0xaa, 0x88);
        uVar16 = lVar4 * 0x6554a2ecfc64bc9d + 0x26c0c6fd1a23bab7;
        local_4460[0] = uVar16;
        lVar6 = 0;
        do {
            uVar16 = (uVar16 >> 4) + *(longlong*)(DAT_18091d4f0 + (ulonglong)((uint)uVar16 & 0xf) * 8);
            local_4460[lVar6+1] = uVar16;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        iVar9 = (int)lVar4;
        uVar16 = (ulonglong)(uVar13 * 4 & 0x1c);
        lVar4 = local_4460[16] * -0x65fa9b5000000000 + local_4460[7] * -0x6f6501d319a0564b + -0x46de1fbc56ed263
            ;
        *(int*)(local_39a0 + uVar10 * 4) =
            ((int)local_4460[7] * -0x10000000 + iVar9 * -0x7ab5183 + 0x73be83d) *
            *(int*)((longlong)DAT_18091d570 + uVar16) + *(int*)((longlong)DAT_18091d590 + uVar16);
        uVar10 = uVar10 + 1;
    } while (uVar10 != 0xba);
   // return; breaks on 74  iVar9
    Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0xa2e);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0xba0);
    lVar4 = 0;
    reg16 xmm0;
    reg16 xmm1;
    reg16 xmm7;
    reg16 xmm8;
    reg16 xmm9;
    reg16 xmm10;
    {
        unsigned char dt[16] = { 4,3,3,6,0,5,3,2,5,1,7,7,7,2,4,4 };
        memcpy(xmm7.data, dt, 16);
    }
 
    do {
        uVar13 = *(uint*)(local_39a0 + lVar4 * 4);
        lVar6 = 0;
        do {
            ((byte *)local_36b0)[lVar6] = (byte)uVar13;
            uVar13 = uVar13 >> 8;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 4);
        ((byte*)local_36b0)[3] = ((byte*)local_36b0)[3] & 0xf;
        local_c60[0] = (int)local_36b0[0];
        local_d0[0] = 7;
        local_d0[1] = 7;
        bVar2 = 0;
        uVar10 = 0;
        do {
            local_d0[uVar10 + 2] =
                *(byte*)((longlong)local_c60 + ((uVar10 & 0xffffffff) >> 2)) >> (bVar2 & 6) & 3;
            uVar10 = uVar10 + 1;
            bVar2 = bVar2 + 2;
        } while (uVar10 != 0xe);
        byte local_16a0[18];
        ConstUser_18016b077(0x1000002db44, local_d0, local_d0, local_16a0);
        local_55d0 = (ulonglong)((uint)lVar4 & 7) * 0x10;
        pbVar1 = DAT_18091d5b0 + local_55d0;
        memcpy(&local_1690[0], xmm7.data, 16);
        local_55c8 = lVar4;
        ConstUser_18016b077(0x1000000d165, local_16a0, local_16a0, local_d0);
        ConstUser_18016b077(0x1000002da8c, pbVar1, pbVar1, (byte*)local_c60);
        ConstUser_18016b077(0x10000002a4a, local_d0, local_d0, (byte *) local_4460);
        iVar9 = 0x1c;
        byte local_c0[20];
        do {
            ConstUser_18016b077(0x10000026678, (byte*)local_c60, (byte *)local_1690, local_4480);
            PFUN_180119595((uint*) DAT_18091d6c0, (uint*)DAT_18136f734, 4, 0x674b7062);
            ConstUser_18016b077(0x1000002d9bb, (byte *)DAT_18136f734, local_4480, local_44a0);
            ConstUser_18016b077(0x1000000a655, local_d0, local_44a0, local_c0);
            ConstUser_18016b077(0x10000018a9d, (byte *)local_4460, local_c0, (byte*)local_4460);
            ConstUser_18016b077(0x10000014ff9, local_d0, local_d0, local_d0);
            ConstUser_18016b077(0x1000001a10c, (byte*)local_1690, (byte*)local_1690, (byte*)local_1690);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        ConstUser_18016b077(0x100000096c9, (byte*) local_4460, local_d0, local_16b0);
        lVar4 = local_55c8;
        ConstUser_18016b077(0x10000033f15, local_16b0, DAT_18091d630 + local_55d0,
            (byte*)(local_2250+ local_55c8*4));
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0xba);
    ConstUser_18016b077(0x1000001ab04, (byte*)local_2250, (byte*)local_2250, local_d0);
   // return;
    Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0xb90);
    lVar4 = 0;
    do {
        pbVar1 = (byte*)((longlong)local_2250 + lVar4 + 0x10);
        ConstUser_18016b077(0x10000034e73, pbVar1, pbVar1, (byte*)((longlong)local_c60 + lVar4));
        lVar4 = lVar4 + 0x10;
    } while (lVar4 != 0xb90);
    puVar14 = (undefined8*)((longlong) local_1690 + 0x10);
    Maybe_MEMSET_180512a50((char*)puVar14, 0xaa, 0xa1e);
    memcpy(local_1690, local_d0, 16);

    lVar4 = 2;
    do {
        uVar23 = *(undefined8*)((longlong)local_c60 + lVar4);
        *(undefined8*)((longlong)puVar14 + 6) = *(undefined8*)((longlong)local_c60 + lVar4 + 6);
        *puVar14 = uVar23;
        puVar14 = (undefined8*)((longlong)puVar14 + 0xe);
        lVar4 = lVar4 + 0x10;
    } while (lVar4 != 0xb92);
    ConstUser_18016b077(0xa2e0000128ba, (byte *)&local_1690[0], (byte*)local_1690, (byte*)local_2c80);
    Maybe_MEMSET_180512a50((char*)local_36b0, 0xaa, 0xa2e);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0xba0);
    lVar4 = 0;
    {
        unsigned char dt[16] = { 3,6,5,1,7,2,0,5,2,0,4,5,3,7,3,7 };
        memcpy(xmm7.data, dt, 16);
    }
  
    do {
        uVar13 = local_4c10[lVar4];
        lVar6 = 0;
        do {
            *(char*)((longlong)&local_5584 + lVar6 ) = (char)uVar13;
            uVar13 = uVar13 >> 8;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 4);
        local_5584 = local_5584 & 0xfffffff;
        local_c60[0] = local_5584;
        *((short*)local_d0) = 0x604;
        bVar2 = 0;
        uVar10 = 0;
        do {
            local_d0[uVar10 + 2] =
                *(byte*)((longlong)local_c60 + ((uVar10 & 0xffffffff) >> 2)) >> (bVar2 & 6) & 3;
            uVar10 = uVar10 + 1;
            bVar2 = bVar2 + 2;
        } while (uVar10 != 0xe);
        ConstUser_18016b077(0x100000282a4, local_d0, local_d0, &local_16b0[16]);
        local_55d0 = (ulonglong)((uint)lVar4 & 7) * 0x10;
        pbVar1 = DAT_18091d6d0 + local_55d0;
        memcpy(local_1690,xmm7.data,16);
        local_55c8 = lVar4;
        ConstUser_18016b077(0x100000166a8, &local_16b0[16], &local_16b0[16], local_d0);
        ConstUser_18016b077(0x100000095f7, pbVar1, pbVar1, (byte*)local_c60);
        ConstUser_18016b077(0x1000000f40f, local_d0, local_d0, (byte*)local_4460);
        iVar9 = 0x1c;
        byte local_c0[18];
        do {
            ConstUser_18016b077(0x10000005a40, (byte*)local_c60, (byte*)local_1690, local_4480);
            PFUN_180119595((uint*)DAT_18091d7e0, (uint*)DAT_18136f748, 4, 0xb08a4a6e);
            ConstUser_18016b077(0x10000020739, DAT_18136f748, local_4480, local_44a0);
            ConstUser_18016b077(0x1000002bae6, local_d0, local_44a0, local_c0);
            ConstUser_18016b077(0x1000002f1cc, (byte*)local_4460, local_c0, (byte*)local_4460);
            ConstUser_18016b077(0x10000006e49, local_d0, local_d0, local_d0);
            ConstUser_18016b077(0x10000033f05, (byte*)local_1690, (byte*)local_1690, (byte*)local_1690);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        ConstUser_18016b077(0x100000230f6, (byte *)local_4460, local_d0, local_16b0);
        lVar4 = local_55c8;
        ConstUser_18016b077(0x100000073d9, local_16b0, DAT_18091d750 + local_55d0, (byte*)(local_2250 + local_55c8 * 4));
        lVar4 = lVar4 + 1;
       
    } while (lVar4 != 0xba);
    ConstUser_18016b077(0x100000206cc, (byte*)local_2250, (byte*)local_2250, local_d0);
    Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0xb90);
    lVar4 = 0;
    do {
        pbVar1 = (byte*)((longlong)local_2250 + lVar4 + 0x10);
        ConstUser_18016b077(0x10000032dba, pbVar1, pbVar1, (byte*)((longlong)local_c60 + lVar4));
        lVar4 = lVar4 + 0x10;
    } while (lVar4 != 0xb90);
    Maybe_MEMSET_180512a50((char*)((longlong) local_1690 + 0x10), 0xaa, 0xa1e);
    puVar14 = (undefined8*)((longlong)local_1690 + 0x10);
    memcpy(local_1690, local_d0, 16);
    lVar4 = 2;
    do {
        uVar23 = *(undefined8*)((longlong)local_c60 + lVar4);
        *(undefined8*)((longlong)puVar14 + 6) = *(undefined8*)((longlong)local_c60 + lVar4 + 6);
        *puVar14 = uVar23;
        puVar14 = (undefined8*)((longlong)puVar14 + 0xe);
        lVar4 = lVar4 + 0x10;
    } while (lVar4 != 0xb92);
    local_55a8 = 0x8010000000f8f;
    ConstUser_18016b077(0xa2e00002bfc9, (byte *)local_1690, (byte*)local_1690, (byte*)local_36b0);
    ConstUser_18016b077(0xa2e00000dff0, (byte*)local_2c80, (byte*)local_36b0, (byte*)local_43d0);
    OtherConstUser_180169484
    (0x518145801706, (byte *)local_43d0, (byte*)local_43d0, (byte*)local_5130);
    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x519);
    Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0x519);
    Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x519);
    MB_Zeropad_180113d26(0x28c0, local_5130, 0x28c8, (byte*)local_2250);
    MB_Zeropad_180113d26(0x28c0, DAT_18091c650, 0x28c8, (byte*)local_c60);
    *(byte *)(&local_2250[326])= 4;
    *(byte*)(&local_c60[326]) = 6;
    ConstUser_18016b077(0x51900002fc56, (byte*)local_2250, (byte*)local_c60, (byte*)local_1690);
    if (((byte*)local_1690)[1304] == '\x01') {
        Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0x5a0);
        Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0x4ee);
        ConstUser_18016b077(0x4ee0000244a7, local_5130, local_5130, (byte*)local_2c80);
        Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x5a0);
        lVar4 = 0;
        iVar9 = 0;
        do {
            lVar6 = (longlong)iVar9;
            uint uVar29 = *(undefined4*)((longlong)local_2c80 + lVar6 + 4);
            uint uVar30 = *(undefined4*)((longlong)local_2c80 + lVar6 + 8);
            uint uVar31 = *(undefined4*)((longlong)local_2c80 + lVar6 + 12);
            *(undefined4*)((longlong)local_2250 + lVar4) = *(undefined4*)((longlong)local_2c80 + lVar6);
            *(undefined4*)((longlong)local_2250 + lVar4 + 4) = uVar29;
            *(undefined4*)((longlong)local_2250 + lVar4 + 8) = uVar30;
            *(undefined4*)((longlong)local_2250 + lVar4 + 0xc) = uVar31;
            iVar9 = iVar9 + 0xe;
            lVar4 = lVar4 + 0x10;
        } while (lVar4 != 0x5a0);
        lVar4 = 0;
        do {
            ConstUser_18016b077(0x1000000c981, (byte*)((longlong)local_2250 + lVar4),
                (byte*)((longlong)local_2250 + lVar4),
                (byte*)((longlong)local_c60 + lVar4));
            lVar4 = lVar4 + 0x10;
        } while (lVar4 != 0x5a0);
        lVar4 = 0;
        {
            unsigned char dt[16] = { 1,4,1,3,3,1,3,3,2,6,0,0,4,4,6,5 };
            memcpy(xmm8.data, dt, 16);
        }

        local_55b8 = 0x12000033e0f;
        local_55c0 = 0x12000006d42;
        local_55c8 = 0x12000013c77;
        memset(xmm10.data, 0, 16);
        {
            unsigned char dt[16] = { 1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1 };
            memcpy(xmm9.data, dt, 16);
        }
        xmm7.PSHUFD(xmm9, 0xf5);

        do {
            uVar10 = (ulonglong)((uint)lVar4 & 7);
            local_55b0 = uVar10 * 9;
            memcpy(local_36b0,xmm8.data, 16);
            *((short*)&local_36b0[2]) = 0x602;
            local_55d0 = lVar4;
            ConstUser_18016b077(local_55b8, DAT_18091d7f0 + uVar10 * 0x12, DAT_18091d7f0 + uVar10 * 0x12,
                (byte*)local_2250);
            OtherConstUser_180169484
            (0x8010000000f8f, (byte*)(local_c60 + lVar4 * 4), (byte*)(local_c60 + lVar4 * 4)
                , (byte*)local_2c80);
            ConstUser_18016b077(local_55c0, (byte*)local_2250, (byte*)local_2250, (byte *)local_43d0);
            iVar8 = 0x1c;
            do {
                ConstUser_18016b077(local_55c8, (byte*)local_2c80, (byte*)local_36b0, local_39a0);
                PFUN_180119595((uint*) DAT_18091d930, (uint*) DAT_18136f75c, 5, 0x775f275c);
                ConstUser_18016b077(0x1200000cfdb, DAT_18136f75c, local_39a0, local_4620);
                ConstUser_18016b077(0x1200000890d, (byte*)local_2250, local_4620, (byte*)local_4460);
                ConstUser_18016b077(0x1200001f771, (byte*)local_43d0, (byte*)local_4460, (byte*)local_43d0);
                ConstUser_18016b077(0x1200000b974, (byte*)local_2250, (byte*)local_2250, (byte*)local_2250);
                ConstUser_18016b077(0x1200003863a, (byte*)local_36b0, (byte*)local_36b0, (byte*)local_36b0);
                iVar8 = iVar8 + -1;
            } while (iVar8 != 0);
            ConstUser_18016b077(0x1200000d23f, (byte*)local_43d0, (byte*)local_2250, local_4480);
            ConstUser_18016b077(0x1200001c076, local_4480, DAT_18091d880 + local_55b0 * 2, local_44a0);
            ConstUser_18016b077(0x1200002df90, local_44a0, local_44a0, (byte*)local_2250);
            ((byte*)local_2250)[17] &= 3;

            local_1690[0] = 0;
            bVar2 = 0;
            uVar10 = 0;
            byte* t_1690 = (byte*)local_1690;
            do {
                t_1690[(uVar10 & 0xffffffff) >> 2] =
                    t_1690[(uVar10 & 0xffffffff) >> 2] |
                    (*(byte*)((longlong)local_2250 + uVar10 + 2) & 3) << (bVar2 & 6);
                uVar10 = uVar10 + 1;
                bVar2 = bVar2 + 2;
            } while (uVar10 != 0x10);
            xmm0.assign4(*(uint*)&local_1690[0]);
            xmm0.PUNPCKLBW(xmm10);
            xmm0.PUNPCKLWD(xmm10);
            xmm1.PSHUFD(xmm0, 0xf5);
            xmm0.PMULUDQ(xmm9);
            xmm0.PSHUFD(xmm0, 0xe8);
            xmm1.PMULUDQ(xmm7);
            xmm1.PSHUFD(xmm1, 0xe8);
            xmm0.PUNPCKLDQ(xmm1);
            xmm1.PSHUFD(xmm0, 0xee);
            xmm1.POR(xmm0);
            xmm0.PSHUFD(xmm1, 0x55);
            xmm0.POR(xmm1);
            local_5580[local_55d0] = *((uint*)xmm0.data);
            lVar4 = local_55d0 + 1;
        } while (lVar4 != 0x5a);
    }
    else {
        Maybe_MEMSET_180512a50((char*)local_1690, 0xaa, 0x518);
        ConstUser_18016b077(0x518000036efd, local_5130, DAT_18091c650, (byte*)local_1690);
        Maybe_MEMSET_180512a50((char*)local_c60, 0xaa, 0x5a0);
        Maybe_MEMSET_180512a50(local_2c80, 0xaa, 0x4ee);
        ConstUser_18016b077(0x4ee0000196ea, (byte*)local_1690, (byte*)local_1690, (byte*)local_2c80);
        Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x5a0);
        lVar4 = 0;
        iVar9 = 0;
        do {
            lVar6 = (longlong)iVar9;
            uint uVar29 = *(undefined4*)((longlong)local_2c80 + lVar6 + 4);
            uint uVar30 = *(undefined4*)((longlong)local_2c80 + lVar6 + 8);
            uint uVar31 = *(undefined4*)((longlong)local_2c80 + lVar6 + 12);
            *(undefined4*)((longlong)local_2250 + lVar4) = *(undefined4*)((longlong)local_2c80 + lVar6);
            *(undefined4*)((longlong)local_2250 + lVar4 + 4) = uVar29;
            *(undefined4*)((longlong)local_2250 + lVar4 + 8) = uVar30;
            *(undefined4*)((longlong)local_2250 + lVar4 + 0xc) = uVar31;
            iVar9 = iVar9 + 0xe;
            lVar4 = lVar4 + 0x10;
        } while (lVar4 != 0x5a0);
        lVar4 = 0;
        do {
            ConstUser_18016b077(0x100000169ac, (byte*)((longlong)local_2250 + lVar4),
                (byte*)((longlong)local_2250 + lVar4),
                (byte*)((longlong)local_c60 + lVar4));
            lVar4 = lVar4 + 0x10;
        } while (lVar4 != 0x5a0);
        lVar4 = 0;
        {
            unsigned char dt[16] = { 2,2,1,7, 3,1,2,6, 0,4,6,6,6,5,2,6 };
            memcpy(xmm8.data, dt, 16);
        }

        local_55b8 = 0x120000046f1;
        local_55a8 = local_55a8 + 0x225e9;
        local_55c0 = 0x12000009adb;
        local_55c8 = 0x12000030712;
        memset(xmm10.data, 0, 16);
        {
            unsigned char dt[16] = { 1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1 };
            memcpy(xmm9.data, dt, 16);
        }
        xmm7.PSHUFD(xmm9, 0xf5);
        do {
            uVar10 = (ulonglong)((uint)lVar4 & 7);
            local_55b0 = uVar10 * 9;
            memcpy(local_36b0, xmm8.data, 16);
            *(short*)&local_36b0[2] = 0x404;
            local_55d0 = lVar4;
            ConstUser_18016b077(local_55b8, DAT_18091d950 + uVar10 * 0x12, DAT_18091d950 + uVar10 * 0x12,
                (byte*)local_2250);
            OtherConstUser_180169484
            (local_55a8, (byte*)(local_c60 + lVar4 * 4), (byte*)(local_c60 + lVar4 * 4),
                (byte*)local_2c80);
            ConstUser_18016b077(local_55c0, (byte*)local_2250, (byte*)local_2250, (byte*)local_43d0);
            iVar8 = 0x1c;
            do {
                ConstUser_18016b077(local_55c8, (byte *)local_2c80, (byte*)local_36b0, local_39a0);
                PFUN_180119595((uint*)DAT_18091da90, (uint*)DAT_18136f774, 5, 0x7d2aa09c);
                ConstUser_18016b077(0x1200001f801, DAT_18136f774, local_39a0, local_4620);
                ConstUser_18016b077(0x1200002afc6, (byte*)local_2250, local_4620, (byte*)local_4460);
                ConstUser_18016b077(0x12000014262, (byte*)local_43d0, (byte*)local_4460, (byte*)local_43d0);
                ConstUser_18016b077(0x1200001534a, (byte*)local_2250, (byte*)local_2250, (byte*)local_2250);
                ConstUser_18016b077(0x120000081da, (byte*)local_36b0, (byte*)local_36b0, (byte*)local_36b0);
                iVar8 = iVar8 + -1;
            } while (iVar8 != 0);
            ConstUser_18016b077(0x120000028de, (byte*)local_43d0, (byte*)local_2250, local_4480);
            ConstUser_18016b077(0x12000008255, local_4480, DAT_18091d9e0 + local_55b0 * 2, local_44a0);
            ConstUser_18016b077(0x12000027a92, local_44a0, local_44a0, (byte*)local_2250);
            ((byte*)local_2250)[17] &= 3; //maybe? TODO
            byte local_c0[32];
            memset(local_c0,0,32); 
            bVar2 = 0;
            uVar10 = 0;
            do {
                local_c0[(uVar10 & 0xffffffff) >> 2] =
                    local_c0[(uVar10 & 0xffffffff) >> 2] |
                    (*(byte*)((longlong)local_2250 + uVar10 + 2) & 3) << (bVar2 & 6);
                uVar10 = uVar10 + 1;
                bVar2 = bVar2 + 2;
            } while (uVar10 != 0x10);
            xmm0.assign4(*(uint*)&local_c0[0]);
            xmm0.PUNPCKLBW(xmm10);
            xmm0.PUNPCKLWD(xmm10);
            xmm1.PSHUFD(xmm0, 0xf5);
            xmm0.PMULUDQ(xmm9);
            xmm0.PSHUFD(xmm0, 0xe8);
            xmm1.PMULUDQ(xmm7);
            xmm1.PSHUFD(xmm1, 0xe8);
            xmm0.PUNPCKLDQ(xmm1);
            xmm1.PSHUFD(xmm0, 0xee);
            xmm1.POR(xmm0);
            xmm0.PSHUFD(xmm1, 0x55);
            xmm0.POR(xmm1);
            local_5580[local_55d0] = *((uint*)xmm0.data);
            lVar4 = local_55d0 + 1;
        } while (lVar4 != 0x5a);
    }

    Maybe_MEMSET_180512a50((char*)local_2250, 0xaa, 0x168);
    lVar4 = 0;
    do {
        local_2250[lVar4] = (INT_18091dab0)[(uint)lVar4 & 7];
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] = local_2250[lVar4] + local_5580[lVar4] * (INT_18091dad0)[(uint)lVar4 & 7];
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    lVar4 = 0;
    do {
        local_2250[lVar4] =
            local_2250[lVar4] + *(int*)(local_55a0 + lVar4 * 4) * (INT_18091daf0)[(uint)lVar4 & 7];
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
    iVar9 = -0x22233bd6;
    lVar4 = 0;
    do {
        iVar8 = iVar9 * 0x70782ecf + local_2250[lVar4];
        uVar13 = iVar8 * 0x217eb811 + 0x8d8149c3;
        local_c60[0] = uVar13;
        lVar6 = 0;
        do {
            uVar13 = (uVar13 >> 4) + (INT_18091db10)[uVar13 & 0xf];
            local_c60[lVar6 + 1] = uVar13;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 8);
        uVar10 = (ulonglong)((int)lVar4 * 4 & 0x1c);
        iVar9 = local_c60[8] * 0x45bf3c10 + local_c60[7] * 0x4ba40c3f + 0x6be06dab;
        output_holder[lVar4] =
            (iVar8 * 0x6ace57cf + local_c60[7] * 0x10000000 + 0x6141bc72) *
            *(int*)((longlong)DAT_18091db50 + uVar10) + *(int*)((longlong)DAT_18091db70 + uVar10);
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5a);
  
    return;
}


void Ecarry_1801a654a(longlong param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_180948c10)[lVar2] +
            (INT_180948c30)[lVar2]) * 0x54fa17cd + 0x6f960056);
    uVar3 = uVar5 * 0x453b62e44d51fa1 + 0x2d564c31a292c450;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_180948c50)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x237c449500000000 + uVar5 * 0x481ec7c9fe91d34b + 0x456897a05384c27c;
    return;
}

void ECarry_Const_1801a65ec(int param_1, longlong* param_2)

{
    ulonglong uVar1;
    ulonglong uVar2;
    longlong lVar3;
    int iVar4;

    lVar3 = (longlong)param_1;
    uVar2 = (ulonglong)
        (((INT_180948be0)[lVar3] * (INT_180948cd0)[lVar3] + *(int*)(DAT_180948ce0 + lVar3 * 4)
            ) * -0x74baf10b + 0x831b174d);
    uVar1 = uVar2 * -0x62a91ef4bb4bb827 + 0x8d31c42f56d6312d;
    iVar4 = 8;
    do {
        uVar1 = (uVar1 >> 4) + (QWORD_180948cf0)[(uint)uVar1 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_2 = uVar1 * -0x7716672900000000 + uVar2 * 0x5f0da9f4956dd0c1 + 0x267ff2033bbfcf6b;
    return;
}

void Ecarrys_1801a6ea1(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * *(int*)(DAT_18094ce70 + lVar2 * 4) +
            *(int*)(DAT_18094ce90 + lVar2 * 4)) * -0x1452894b + 0x744bc4c9);
    uVar3 = uVar5 * -0x7d9ec764b97d3339 + 0x19a4e8ec2f099b4e;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094ceb0 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x59c248bd00000000 + uVar5 * 0x77461faaca08d915 + 0x4f1354302ee1ef93;
    return;
}

//
void Ecarrys_1801a6dff(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094cdb0)[lVar2] + (INT_18094cdd0)[lVar2]) * 0x56d6331f
            + 0x8bf43d9c);
    uVar3 = uVar5 * 0xff7a23336073fdf + 0x3f07cbe93b13ca9f;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094cdf0 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x28fe28bf00000000 + uVar5 * -0x17095e9f575a809f + 0x4ffaec763bfe52d9;
    return;
}

void Ecarry_4_1801a67ab(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_1809498f0)[lVar2] + (INT_180949910)[lVar2]) * -0x634ba7fb
            + 0x6d0fab97);
    uVar3 = uVar5 * 0x25634230e70bea63 + 0x60f47c5f4f1f03af;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_180949930)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x45923d0b00000000 + uVar5 * 0x480c64d91fd2a941 + -0x663dc0ae1b7cd9c8;
    return;
}
void Ecarrys_1801a6c19(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094b330)[lVar2] + (INT_18094b350)[lVar2]) * 0x662ea0f7
            + 0x764d3ded);
    uVar3 = uVar5 * 0x4bc91dd94a87f809 + 0xeadef877860b6109;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094b370 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x183ca8fb00000000 + uVar5 * -0x5656be63483218d3 + -0x48b2428434c9a9fd;
    return;
}


void Ecarrys_1801a6b77(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_18094b270)[lVar2] + (INT_18094b290)[lVar2]) * 0x5a1248d9
            + 0x3a393ad6);
    uVar3 = uVar5 * -0x32e3e2f1144e3073 + 0xcdba1e3e590da48d;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094b2b0 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x16b8b27f00000000 + uVar5 * 0x756948a3dade00f3 + 0x6032a1f0b9c37edc;
    return;
}


void Ecarry_5_1801a684d(int* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((param_1[(int)param_2] * (INT_1809499b0)[lVar2] + (INT_1809499d0)[lVar2]) * 0x1ef606b9
            + 0x4bfe7c81);
    uVar3 = uVar5 * 0x1ad2759c3ec6b991 + 0xf56cf10141acf21d;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_1809499f0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x51c4a51b00000000 + uVar5 * -0x389a4a14576bf8b5 + -0x271adf416c61f618;
    return;
}


void ECarry_3_1801a671a(int* param_1, int param_2, longlong* param_3)

{
    longlong lVar1;
    ulonglong uVar2;
    int iVar3;
    ulonglong uVar4;

    lVar1 = (longlong)param_2;
    uVar4 = (ulonglong)
        ((param_1[lVar1] * (INT_180949110)[lVar1] + (INT_180949130)[lVar1]) * 0x16324c93 +
            0xa26ff6c6);
    uVar2 = uVar4 * 0x30e23d5de570da7 + 0x53a94621053011a8;
    iVar3 = 8;
    do {
        uVar2 = (uVar2 >> 4) + (QWORD_180949150)[(uint)uVar2 & 0xf];
        iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    *param_3 = uVar2 * -0x622cfec100000000 + uVar4 * -0x56806275ba1f0319 + -0x4c8587ad856fc5ab;
    return;
}

void Ecarrys_1801a68ef(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * *(int*)(DAT_18094a130 + lVar2 * 4) +
            *(int*)(DAT_18094a150 + lVar2 * 4)) * 0x3596f057 + 0xcee61129);
    uVar3 = uVar5 * -0x3ddb6a34e3992851 + 0xba98710936f5ec78;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094a170 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x15413cdb00000000 + uVar5 * 0x5349f09984f686b5 + 0x374048ddc2bbcecb;
    return;
}

void Ecarrys_1801a6991(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * *(int*)(DAT_18094a1f0 + lVar2 * 4) +
            *(int*)(DAT_18094a210 + lVar2 * 4)) * -0x5e0dab25 + 0x5e7fd546);
    uVar3 = uVar5 * 0x7e1487ec173690c7 + 0xa6b9954746e9f83c;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094a230 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x336e3f0700000000 + uVar5 * 0x18248a0ceaa0ee71 + 0x12bb8b48dc6ceb11;
    return;
}

void Ecarrys_1801a6f43(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * *(int*)(DAT_18094d230 + lVar2 * 4) +
            *(int*)(DAT_18094d250 + lVar2 * 4)) * 0x5b52205d + 0x4f6b116e);
    uVar3 = uVar5 * 0x761cf9351985663d + 0x4982378c33662526;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094d270 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x206ef50b00000000 + uVar5 * 0x19db8fc5ae363a61 + 0x11f4baf5660b73df;
    return;
}

void Ecarrys_1801a6fe5(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * *(int*)(DAT_18094d2f0 + lVar2 * 4) +
            *(int*)(DAT_18094d310 + lVar2 * 4)) * 0x6edc7ed9 + 0x59bba14e);
    uVar3 = uVar5 * 0x23bc6785f0c1e9dd + 0xe672fd88f1c43261;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + *(longlong*)(DAT_18094d330 + (ulonglong)((uint)uVar3 & 0xf) * 8);
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x1f55453100000000 + uVar5 * -0x4c5fb688c287544d + 0x7958202f3dd0aeab;
    return;
}

void ECCarry_1801a617e(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091ef30)[lVar2] +
            (INT_18091ef50)[lVar2]) * -0x6eb8625 + 0x2e47aeaf);
    uVar3 = uVar5 * 0x3a9e4a87b0eb66b + 0xb2d7625d2628403b;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091ef70)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x66c8663d00000000 + uVar5 * -0x5fb1325fab37e681 + -0x33c320ebe0b0e4fe;
    return;
}

void ECCarry_1801a6220(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091eff0)[lVar2] +
            (INT_18091f010)[lVar2]) * -0x65cafbd + 0xd65743d0);
    uVar3 = uVar5 * -0x22d00e1e95cf97e5 + 0xedbc181b5f8e0fac;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091f030)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x6c1e09fd00000000 + uVar5 * -0x3e5d4bedc3562a51 + -0x75c984a1b47891ff;
    return;
}
void ECCarry_1801a6364(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091f470)[lVar2] +
            (INT_18091f490)[lVar2]) * 0x5cd1da43 + 0x37b0a91);
    uVar3 = uVar5 * 0x4d4a75cc86d5dfcd + 0x96f4d29e0c12aaab;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091f4b0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x35cf785300000000 + uVar5 * -0x6cfb1b919ffd5889 + 0xf64555f756a82b0;
    return;
}

void ECCarry_1801a62c2(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091f3b0)[lVar2] +
            (INT_18091f3d0)[lVar2]) * -0x581e929f + 0xa77eed3a);
    uVar3 = uVar5 * -0x47932cfc10d34075 + 0xbabce08a5faba781;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091f3f0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x1c786baf00000000 + uVar5 * 0x705cb6fccf31f6fb + 0x491ab4eff01cfd16;
    return;
}




void ConstMultiplier_18019c629(byte* param_1, longlong param_2, longlong param_3, longlong varx)

{
    int* piVar1;
    byte* pdat;
    longlong lVar3;
    int* piVar4;
    uint uVar5;
    longlong lVar7;
    int iVar8;
    int iVar9;
    uint uVar10;
    int iVar11;
    longlong lVar12;
    ulonglong uVar13;
    ulonglong uVar14;
    int iVar15;
    longlong lVar16;
    ulonglong uVar17;
    longlong lVar18;
    byte bVar19;
    byte* pbVar20;
    byte* pbVar21;
    ulonglong* puVar22;
    ulonglong uVar23;
    ulonglong uVar24;
    uint uVar25;
    byte* pbVar27;
    undefined4 uVar34;
    undefined4 uVar35;
    undefined4 uVar37;
    undefined4 uVar38;
    int iVar39;
    int iVar40;
    int iVar41;
    int iVar42;
    int iVar43;
    byte* local_42f0;
    longlong local_42e8;
    int* local_42e0;
    byte* local_42d8;
    int* local_42d0;
    byte* local_42c8;
    int local_42c0[4];
    uint local_42a4;
    uint local_42a0[4];
    byte local_4290[1026];
    byte local_3e88[1032];
    int local_3a80[80];
    undefined8 local_3940[32];
    byte local_3840[1027];
    int local_3430[92];
    int local_32c0[92];
    byte local_3150[136];
    byte local_30c0[1440];
    byte local_2b20[1227];
    byte local_2710[1062];
    byte local_22e0[1024];
    byte local_22b0[1063];
    int local_1e80[268];
    ulonglong local_1a50[180];
    byte local_1620[1232+1720];
    byte* local_1170=(byte*)(local_1620 + 0x4b0);
    byte local_d40[1462];
    byte local_910[1062];
    byte local_4e0[1062];
    local_42c0[0] = -0x55555556;
    local_42c0[1] = -0x55555556;
    local_42c0[2] = -0x55555556;
    local_42c0[3] = -0x55555556;
    
    reg16 xmm0, xmm1, xmm2,xmm3,xmm4,xmm5,  xmm7, xmm8, xmm9, xmm10,xmm11,tmp;
    memcpy(xmm0.data, &param_1[0x3938], 16);
    {
        unsigned char dt[16] = {0xd3,0x79,0x30,0x97,0xa7,0x46,0xa0,0x9e,0x0f,0x6b,0x06,0x59,0x19,0x5d,0xfe,0x17};
        memcpy(xmm1.data, dt, 16);
    }
    xmm2.PSHUFD(xmm0, 0xf5);
    xmm0.PMULUDQ(xmm1);
    xmm0.PSHUFD(xmm0, 0xe8);
    xmm1.PSHUFD(xmm1, 0xf5);
    xmm1.PMULUDQ(xmm2);
    xmm1.PSHUFD(xmm1, 0xe8);
    xmm0.PUNPCKLDQ(xmm1);
    {
        unsigned char dt[16] = { 0x1e,0x7e,0xd5,0x44,0x12,0xde,0x91,0x11,0x47,0x51,0xe2,0x81,0x9d,0x5d,0x6e,0x8d };
        memcpy(tmp.data, dt, 16);
    }
    xmm0.PADDD(tmp);
    memcpy(local_d40, xmm0.data, 16);
    {
        unsigned char dt[16] = { 0x2e,0x3a,0xe1,0x34,0x9c,0xcd,0x52,0xee,0x03, 0x4b,0xf0,0x63,0xa5,0x99,0x32,0x4e };
        memcpy(xmm0.data, dt, 16);
    }
    memcpy(&local_d40[16], xmm0.data, 16);

    pbVar20 = local_30c0;
    local_42e0 = (int*)param_3;
    local_42c8 = (byte*)varx;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x310);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Ecarry_1801a654a(param_2, 0, (longlong*)local_4e0);
    ECarry_Const_1801a65ec(0, (longlong*)local_1a50);
    longlong rdi = *(longlong*)local_4e0;
    *(longlong*)local_910 = rdi;
    longlong r14 = *(longlong*)local_1a50;
    *(longlong*)local_1620 = r14;
    lVar12 = 1;
    lVar16 = 8;
 
    do {
        Ecarry_1801a654a(param_2, (uint)lVar12, (longlong*)(local_4e0 + lVar16));
        rdi= rdi+ *(longlong*)(local_4e0 + lVar12 * 8);
        *(longlong*)(local_910 + lVar12 * 8) = rdi;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    lVar16 = 1;
    lVar12 = 8;
    local_42f0 = param_1;
    do {
        ECarry_Const_1801a65ec((int)lVar16, (longlong*)((longlong)local_1a50 + lVar12));
        r14 = r14 + local_1a50[lVar16];
        *(ulonglong*)(local_1620 + lVar16 * 8) =r14;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 4);
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 3);
        if (uVar10 < 3) {
            uVar17 = 0;
        }
        lVar12 = 0x26c3d3e0d4ffdfed;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + local_1a50[uVar13 & 0xffffffff] * *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_910 + uVar14 * 8);
            if (3 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_910 + (ulonglong)(uVar5 - 1) * 8);
            }
            lVar7 = *(longlong*)(local_1620 + (ulonglong)(uVar10 - uVar5) * 8);
            if (0x59 < uVar23) {
                lVar7 = lVar7 - *(longlong*)(local_1620 + (ulonglong)(~uVar25 + uVar10) * 8);
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * 0x10f411fbac2ff3da + 0x26c3d3e0d4ffdfed +
                lVar12 * -0x2453ae80981c9c41 + lVar16 * 0x44c76415aa3f02ab +
                lVar7 * 0x16347e3ada3528f2;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * 0x331c2266e1b1e5af + -0x93ec71362cec0b4;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0x62);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((uint)
            ((*(int*)((longlong)DAT_180948bd0 + lVar12 * 4) *
                *(int*)((longlong)DAT_180948d70 + lVar12 * 4) +
                *(int*)((longlong)DAT_180948d80 + lVar12 * 4)) * 0x1a4533ed + 0x193b42dc));
        uVar14 = uVar23 * -0x66b0cbdb119d75ff + 0xe3afefc012328fad;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_180948d90 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        local_1a50[lVar12] =
            uVar14 * 0x2a59c4c900000000 + uVar23 * -0x4d11d8c6c1601ec9 + 0x487373e2e08c0703;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 4);
    lVar12 = 0;
    longlong tmpout = *(longlong*)local_30c0;
    do {
        lVar16 = tmpout * 0x267f558ac4e8607d + -0x79d4a3f3c344a53d;
        uVar23 = lVar16 * 0x26fc428c997ad2d9 + 0x2e3fbb74eba7aa1;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180948e10 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x747aff1590000000 + lVar16 * 0x6f07f08d4d889671 + 0x482484af01d2fcdc;
        lVar16 = lVar7 * 0x3e3c640518c402a1 + 0x42360de335f969ee;
        uVar23 = lVar7 * 0x7914e400dd421b73 + 0x632bc8df471451aa;
        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);

        lVar7 = 0;
        do {
            uVar14 = local_1a50[lVar7];
            uVar17 = local_1a50[lVar7 + 1];
            memcpy(xmm2.data, &local_1a50[lVar7], 16);
            memcpy(xmm3.data,&pbVar20[lVar7 * 8],16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy( &pbVar20[lVar7 * 8],xmm2.data, 16);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            lVar7 = lVar7 + 2;
        } while (lVar7 != 4);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * -0x6c05d0b613a2437b + 0x95266a58df89664;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180948e90 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x680734c5d534678f + 0x1d5f5cfaf99a0614;
        uVar23 = lVar16 * 0x1b2b916fbe91b7af + 0x6e3aa7b9b0dbff48;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180948f10 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        tmpout =
            (uVar23 * -0x79adfbb000000000 + lVar16 * 0x466705433bb89dd5) * 0x26a46eae744026a9 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + -0x6312229e37b32279;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tmpout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = 0x4e11a14a1a7addf6;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x572d16340d2607f9 +
            lVar12 * -0x4aed14d03d0e9f5d + 0xbbde0b1d1042272;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x3f2c2687dbaa029d + 0xb79fc897b7ea6379;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180948f90 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        lVar12 = *(longlong *)(&local_3150[128]) * 0x1207c7000000000 + *(longlong*)(&local_3150[56]) * -0x79bbd1b7501207c7 +
            -0x4edea0337814009a;
        *(int*)(local_1620 + lVar16 * 4 + 0x348) =
            ((int)*(longlong*)(&local_3150[56]) * 0x70000000 + (int)lVar7 * -0x11ede8f5 + 0x65edc940) *
            *(int*)(DAT_180948ea8 + lVar16 * 4) + *(int*)(DAT_180948ea8 +0x20+ lVar16 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0x62);
    lVar12 = 0x123;
    {
        unsigned char dt[16] = {0x92,0xc0,0x0c,0x10,0xd4,0x27,0x82,0xf4,0x14,0x50,0x0d,0x18,0x6e,0xea,0x0c,0x11};
        memcpy(xmm8.data, dt, 16);
    }
 
    {
        unsigned char dt[16] = {0x27,0x50,0xca,0xea,0xe0,0xc3,0xda,0x36,0xf4,0x36,0x89,0x32,0x5b,0x19,0xc2,0xca};
        memcpy(xmm9.data, dt, 16);

    }
  
    {
        unsigned char dt[16] = {0x4d,0x14,0x80,0x52,0x0f,0x40,0x21,0xdd,0xcb,0x2b,0xf5,0xcd,0x65,0xd5,0x39,0xcb};
        memcpy(xmm10.data, dt, 16);
    }
    xmm7.PSHUFD(xmm10, 0xf5);
    {
        unsigned char dt[16] = { 0xec,0x97,0xc1,0x20,0x85,0xd7,0x54,0xbc,0xd4,0x5d,0x48,0xdb,0x11,0xfd,0x82,0x7f};
        memcpy(xmm11.data, dt, 16);
    }
    iVar9 = -0xb7dd82c;
    iVar11 = 0x180d5014;
    iVar39 = 0x110cea6e;
    iVar40 = -0x1535afd9;
    iVar41 = 0x36dac3e0;
    iVar42 = 0x328936f4;
    iVar43 = -0x353de6a5;


    do {
        local_42e8 = lVar12;
        Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x310);
        ECarry_1801a6689((int*)local_d40, 0, (longlong*)local_1620);
        ECarry_3_1801a671a((int*)(local_1620 + 0x4b0), 0, (longlong*)local_1a50);
        *(ulonglong*)local_4e0 = *(ulonglong*)local_1620;
        *(ulonglong*)local_910 = local_1a50[0];
        lVar12 = 1;
        lVar16 = 8;
        longlong tmpw = *(longlong*)local_1620;
        do {
            ECarry_1801a6689((int*)local_d40, (int)lVar12, (longlong*)(local_1620 + lVar16));
           tmpw =tmpw + *(longlong*)(local_1620 + lVar12 * 8);
            *(ulonglong*)(local_4e0 + lVar12 * 8) = tmpw;
            lVar12 = lVar12 + 1;
            lVar16 = lVar16 + 8;
        } while (lVar12 != 8);
        lVar12 = 1;
        lVar16 = 8;
        tmpw = local_1a50[0];
        do {
            ECarry_3_1801a671a((int*)(local_1620 + 0x4b0), (int)lVar12, (longlong*)((longlong)local_1a50 + lVar16));
            tmpw =tmpw + local_1a50[lVar12];
            *(ulonglong*)(local_910 + lVar12 * 8) = tmpw;
            lVar12 = lVar12 + 1;
            lVar16 = lVar16 + 8;
        } while (lVar12 != 8);
        uVar23 = 0;
        do {
            uVar14 = 7;
            if (uVar23 < 7) {
                uVar14 = uVar23;
            }
            uVar10 = (uint)uVar23;
            uVar17 = (ulonglong)(uVar10 - 7);
            if (uVar10 < 7) {
                uVar17 = 0;
            }
            lVar12 = 0x6b68b34fc4227e44;
            uVar25 = (uint)uVar14;
            uVar5 = (uint)uVar17;
            if (uVar5 <= uVar25) {
                uVar13 = uVar23 - uVar17;
                lVar12 = 0;
                do {
                    lVar12 = lVar12 + local_1a50[uVar13 & 0xffffffff] * *(longlong*)(local_1620 + uVar17 * 8)
                        ;
                    uVar17 = uVar17 + 1;
                    uVar13 = uVar13 - 1;
                } while (uVar14 + 1 != uVar17);
                lVar16 = *(longlong*)(local_4e0 + uVar14 * 8);
                if (7 < uVar23) {
                    lVar16 = lVar16 - *(longlong*)(local_4e0 + (ulonglong)(uVar5 - 1) * 8);
                }
                lVar7 = *(longlong*)(local_910 + (ulonglong)(uVar10 - uVar5) * 8);
                if (7 < uVar23) {
                    lVar7 = lVar7 - *(longlong*)(local_910 + (ulonglong)(~uVar25 + uVar10) * 8);
                }
                lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0x1bade8868ee99a60 + 0x6b68b34fc4227e44 +
                    lVar12 * -0x2a428692ee8908f7 + lVar16 * -0x35755085280d712c +
                    lVar7 * 0x38cb5dba77af8308;
            }
            *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * 0x6adce5fb130e7769 + -0x1359c1c45ef89c2f;
            uVar23 = uVar23 + 1;
        } while (uVar23 != 0x62);
        lVar12 = 0;
        do {
            uVar23 = (ulonglong)
                ((*(int*)((longlong)DAT_180948bd0 + lVar12 * 4) *
                    *(int*)((longlong)DAT_1809491d0 + lVar12 * 4) +
                    *(int*)((longlong)DAT_1809491e0 + lVar12 * 4)) * -0x29fa0f9f + 0x3c0d243f);
            uVar14 = uVar23 * -0x6dee61ba3bff327f + 0xf785c0424d369bdb;
            iVar15 = 8;
            do {
                uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_1809491f0 + (ulonglong)((uint)uVar14 & 0xf) * 8)
                    ;
                iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            local_1a50[lVar12] =
                uVar14 * 0x50a640fd00000000 + uVar23 * -0x49c5930879d1587d + 0x18a21f597b65cf78;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 4);
        pbVar20 = local_30c0;
        lVar12 = 0;
        tmpout = *(longlong*)local_30c0;
        do {
            lVar16 = tmpout * -0x29bcb979daadc687 + -0x5de9231ee59ca963;
            uVar23 = lVar16 * -0x4613417a4afa3ec3 + 0x2050429c29749522;
            iVar15 = 7;
            do {
                uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949270 + (ulonglong)((uint)uVar23 & 0xf) * 8)
                    ;
                iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            lVar16 = uVar23 * 0x2f09f90590000000 + lVar16 * -0x2ab748d560957e35 + 0xe7a943e63fb74ff;
            lVar7 = lVar16 * 0x2b004e9a32417c6b + -0x53cb1d921db3962f;
            uVar23 = lVar16 * -0x599e0698e8f6db1 + 0xe6e1a67f1b569c3d;
            xmm0.assign8(uVar23);
            xmm0.PSHUFD(xmm0, 0x44);
            xmm1.assign8(lVar7);
            xmm1.PSHUFD(xmm1, 0x44);


            lVar16 = 0;
            do {
         
                lVar18 = *(longlong*)((longlong)(pbVar20 + lVar16 * 8) + 8);
                memcpy(xmm2.data, &local_1a50[lVar16], 16);
                memcpy(xmm3.data, pbVar20 + lVar16 * 8, 16);
                xmm3.PADDQ(xmm1);
                memcpy(xmm4.data, xmm0.data,16);
                xmm4.PSRLQ(0x20);
                xmm4.PMULUDQ(xmm2);
                memcpy(xmm5.data, xmm2.data, 16);
                xmm5.PSRLQ(0x20);
                xmm5.PMULUDQ(xmm0);
                xmm5.PADDQ(xmm4);
                xmm5.PSLLQ(0x20);
                xmm2.PMULUDQ(xmm0);
                xmm2.PADDQ(xmm5);
                xmm2.PADDQ(xmm3);
                memcpy(pbVar20 + lVar16 * 8,xmm2.data,16);
                lVar16 = lVar16 + 2;
            } while (lVar16 != 4);
            uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x6b9bb795fcee6ba3 + 0xa179e4f8ab2fda0b;
            iVar15 = 7;
            do {
                uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_1809492f0 + (ulonglong)((uint)uVar23 & 0xf) * 8)
                    ;
                iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            lVar16 = uVar23 * 0x7534fd8e9de2c93 + 0x18da367e512eb29a;
            uVar23 = lVar16 * 0x119ae4f75755c977 + 0xe119db825e8f4f96;
            iVar15 = 9;
            do {
                uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949370 + (ulonglong)((uint)uVar23 & 0xf) * 8)
                    ;
                iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            tmpout =
                (uVar23 * -0x664f8a9000000000 + lVar16 * -0x3e24882760b6b871) * -0x4f0c0acc4ad298b9 +
                *(longlong*)(local_30c0 + lVar12 * 8 + 8) + -0x623f6478ce98d2cf;
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tmpout;
            lVar12 = lVar12 + 1;
            pbVar20 = pbVar20 + 8;
        } while (lVar12 != 0x5a);
        lVar16 = 0x5a;
        lVar12 = -0x207577193331fecc;
        do {
            lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0xa1ff17f17ba30b1 +
                lVar12 * -0x34cb38e4d58bdf47 + 0x21198bec3f23e89d;
            Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
            uVar23 = lVar7 * 0x693600e3ca378c6b + 0x8352731f228dcb7a;
            *(ulonglong*)local_3150 = uVar23;
            lVar12 = 0;
            do {
                uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_1809493f0 + (ulonglong)((uint)uVar23 & 0xf) * 8)
                    ;
                *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
                lVar12 = lVar12 + 1;
            } while (lVar12 != 0x10);
            lVar12 = *(longlong *)(&local_3150[128]) * -0x25bd2db000000000 + *(longlong*)(&local_3150[56]) * -0x13512ac85da42d25 +
                0x6421399e73922ad0;
            *(int*)(&local_22b0[lVar16*4-0x168]) =
                ((int)*(longlong*)(&local_3150[56]) * -0x10000000 + (int)lVar7 * -0x63d02a65 + 0x31aba140) *
                *(int*)(DAT_180949308 + lVar16 * 4) + *(int*)(DAT_180949308 +0x20+ lVar16 * 4);
            lVar16 = lVar16 + 1;
        } while (lVar16 != 0x62);
        memcpy(&local_30c0[16], xmm9.data, 16);
        iVar15 = *(int *)local_22b0 * -0x3fe9a37f + 0x100cc092;
        memcpy(local_30c0,xmm8.data,16);
        *(int*)local_30c0 = iVar15;
        lVar12 = 1;
        do {
            *(int*)(local_30c0 + lVar12 * 4) =
                *(int*)(local_30c0 + lVar12 * 4) +
                *(int*)(local_22b0 + lVar12 * 4) * *(int*)(DAT_1809494d0 + lVar12 * 4);
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        memcpy(xmm0.data, local_42f0 + 0x26f8 + (longlong)local_42e8 * 0x10, 16);
        xmm1.PSHUFD(xmm0, 0xf5);
        xmm0.PMULUDQ(xmm10);
        xmm0.PSHUFD(xmm0, 0xe8);
        xmm1.PMULUDQ(xmm7);
        xmm1.PSHUFD(xmm1, 0xe8);
        xmm0.PUNPCKLDQ(xmm1);
        memcpy(tmp.data, local_30c0, 16);
        xmm0.PADDD(tmp);
        memcpy(local_30c0, xmm0.data,16);
        memcpy(xmm0.data, &local_30c0[16], 16);
        xmm0.PADDD(xmm11);
        memcpy( &local_30c0[16], xmm0.data,16);
        iVar15 = 0x2b2d031e;
        lVar12 = 0;
        do {
            iVar8 = iVar15 * -0x5d09c541 + *(int*)(local_30c0 + lVar12 * 4);
            uVar10 = iVar8 * 0x75550e09 + 0xdd3e4bef;
            *(uint*)local_1620 =  uVar10;
            lVar16 = 0;
            do {
                uVar10 = (uVar10 >> 4) + *(int*)(DAT_1809494f0 + (ulonglong)(uVar10 & 0xf) * 4);
                *(uint*)(local_1620 + lVar16 * 4 + 4) = uVar10;
                lVar16 = lVar16 + 1;
            } while (lVar16 != 8);
            iVar15 = *(int *)(&local_1620[28]) * -0x563304f9 + *(int*)(&local_1620[32]) * 0x63304f90 + -0x61f5f181;
            *(int*)(local_d40 + lVar12 * 4) =
                (*(int*)(&local_1620[28]) * 0x50000000 + iVar8 * -0x57eaa97d + -0x7b8070b1) *
                *(int*)((longlong)DAT_180949530 + lVar12 * 4) +
                *(int*)((longlong)DAT_180949550 + lVar12 * 4);
            lVar12 = lVar12 + 1; //1 OK at 10%
        } while (lVar12 != 8);
        lVar12 = (longlong)local_42e8 + -1;
    } while (local_42e8 != 0x0);
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x2f0);
    uVar23 = 0;
    do {
        lVar12 = 0x66f2f29d0ce03b36;
        if (uVar23 < 8) {
            uVar17 = (ulonglong)
                ((*(int*)(local_d40 + uVar23 * 4) * *(int*)((longlong)DAT_180949570 + uVar23 * 4)
                    + *(int*)((longlong)DAT_180949590 + uVar23 * 4)) * 0x104c0101 + 0x86606262);
            uVar14 = uVar17 * -0x5f03576c6f81f1fd + 0xc52c008b13618a09;
            iVar9 = 8;
            do {
                uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_1809495b0 + (ulonglong)((uint)uVar14 & 0xf) * 8)
                    ;
                iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
            lVar12 = uVar14 * 0x6b6fd61500000000 + uVar17 * -0x70eb1e998e5aa83f + -0x228751dc82f2856c;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0x5e);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)
            ((*(int*)((longlong)DAT_180948bd0 + lVar12 * 4) *
                *(int*)((longlong)DAT_180949630 + lVar12 * 4) +
                *(int*)((longlong)DAT_180949640 + lVar12 * 4)) * -0x1d8f6903 + 0xf429e90c);
        uVar14 = uVar23 * 0x6d976f0f0565a71 + 0xe13ef35c085c5195;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_180949650 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        local_1a50[lVar12] =
            uVar14 * 0x2f703e4b00000000 + uVar23 * 0x19ab8d355c5c22e5 + 0x69928c2d52dc0336;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 4);
    lVar12 = 0;
    longlong tempout = *(longlong*)local_30c0;
    do {
        lVar16 =tempout * 0x3e934ff9f760ebad + -0x135cb663b603c895;
        uVar23 = lVar16 * -0x216b90529fd2a875 + 0x636765c22bfd63e3;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_1809496d0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x21a814d8f0000000 + lVar16 * -0x623a5156684c4a5b + -0x5d5fea06c3db9a99;
        lVar16 = lVar7 * 0x7cc74b6dc71b17df + -0x4a34b4527c7918ec;
        uVar23 = lVar7 * -0x55a17382924fee5b + 0x55777e8e186e489c;
        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);

        lVar7 = 0;
        do {
            uVar14 = local_1a50[lVar7];
            uVar17 = local_1a50[lVar7 + 1];
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            memcpy(xmm2.data, local_1a50 + lVar7 , 16);
            memcpy(xmm3.data, pbVar20 + lVar7 * 8, 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(pbVar20 + lVar7 * 8, xmm2.data, 16);
            //TODO -maybe?
            lVar7 = lVar7 + 2;
        } while (lVar7 != 4);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x7142695967b14d57 + 0xd1a0be5dd3004711;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949750 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * 0x75c478e232cb94f7 + 0x4477d063be65b297;
        uVar23 = lVar16 * 0x1b4e1b25cf27980f + 0x989c29123c625c19;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_1809497d0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
         tempout  =
            (uVar23 * 0x43cbd1b000000000 + lVar16 * -0x452b886893f41c95) * -0x1f13ca207f4ce88d +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x46d7d29748e7c0fc;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = -0x41fb026b635efb4d;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0x6d7ab9bb4e307389 +
            lVar12 * 0x376408538a49092b + 0x52f109eb4c3c6832;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x6a9c6f8399fd9d + 0x7946f818a601891e;
        *(ulonglong*)local_3150 =  uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949850 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        lVar12 = *(longlong *)(&local_3150[128]) * -0x62d4261000000000 + *(longlong*)(&local_3150[56]) * 0x4f4315e4a62d4261 +
            0x7895d0167ad9fd5a;
        local_42c0[lVar16-0x5a] =
            ((int)*(longlong*)(&local_3150[56]) * 0x50000000 + (int)lVar7 * 0xb10fd11 + 0x7139443e) *
            *(int*)(DAT_180949768 + lVar16 * 4) + *(int*)(DAT_180949778 + lVar16 * 4);
        lVar16 = lVar16 + 1; //CHECKED, seems ok
    } while (lVar16 != 0x5e);
    Maybe_MEMSET_180512a50((char*)local_32c0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x168);
    local_42e8 = *(longlong*)(local_42f0 + 0xf18);
    piVar1 = (int*)(local_42f0 + 0x10c8);
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    piVar4 = local_42e0;
    Ecarry_4_1801a67ab(local_42e0, 0, (longlong*)local_4e0);
    Ecarry_5_1801a684d(piVar1, 0, (longlong*)local_910); //CHECKED, seems ok
    *(longlong*)local_1620 = *(longlong*)local_4e0;
    local_1a50[0] = *(ulonglong*)local_910;
    lVar12 = 1;
    lVar16 = 8;
    longlong tmpk= *(longlong*)local_4e0;
    do {
        Ecarry_4_1801a67ab(piVar4, (uint)lVar12, (longlong*)(local_4e0 + lVar16));
        tmpk = tmpk + *(longlong*)(local_4e0 + lVar12 * 8);
        *(longlong*)(local_1620 + lVar12 * 8) = tmpk;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = 1;
    lVar16 = 8;
    longlong tmpw = *(longlong*)local_910;
    do {
        Ecarry_5_1801a684d(piVar1, (uint)lVar12, (longlong*)(local_910 + lVar16));
         tmpw = tmpw + *(longlong*)(local_910 + lVar12 * 8);
        local_1a50[lVar12] = tmpw;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = -0x2b477c1c9176cc30;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + *(longlong*)(local_910 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_1620 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_1620 + (ulonglong)(uVar5 - 1) * 8);
            }
            uVar14 = local_1a50[uVar10 - uVar5];
            if (0x59 < uVar23) {
                uVar14 = uVar14 - local_1a50[~uVar25 + uVar10];
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0xa8a8f39c529a0d4 + -0x2b477c1c9176cc30 +
                lVar12 * -0x102438dd5ee43c5b + lVar16 * -0x5278a789754800c4 +
                uVar14 * 0x70bec2e7bcd71279;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * 0x518e4c043986027f + -0x716e08ddb66b630d;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4); //seems OK... CHECKED
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(local_42f0 + lVar12 * 4 + 0xad8) *
                *(int*)((longlong)DAT_180949a70 + uVar23) +
                *(int*)((longlong)DAT_180949a90 + uVar23)) * -0x2276f7cd + 0xf84d74b2);
        uVar14 = uVar23 * 0x3c2575873b5f5645 + 0xbe342fdbb7b888ba;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_180949ab0 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_4e0 + lVar12 * 8) =
            uVar14 * -0x734d94c100000000 + uVar23 * 0x8bb9120d280ee05 + 0x2c6b8480c6a581e4;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)(&local_30c0[0]);
    do {
        lVar16 = tempout * ((longlong)local_42e8 * 0x7d5c01f0954cf1a1 + 0x48c6b4d06f61f24e) +
            (longlong)local_42e8 * 0x8c0a10dc69665fd + -0x2c33f27ec8460471;
        uVar23 = lVar16 * -0x22ba51f1274bfab9 + 0x9c3c02edfb7dd976;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949b30 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * 0x8ac0ec2b0000000 + lVar16 * 0x45a3d50f69a5a913 + 0x3282846139ee6961;
        lVar16 = lVar7 * -0x5b4b13b29b552f8c + -0x743b4e2ba11976b0;
        uVar23 = lVar7 * 0x21f15e9034f20e83 + 0x7418753693f8442c;
        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_4e0 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_4e0 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            memcpy(xmm2.data, local_4e0 + lVar7 * 8, 16);
            memcpy(xmm3.data, pbVar20 + lVar7 * 8, 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(pbVar20 + lVar7 * 8, xmm2.data, 16);
            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x4a7462f7c2dad1f + 0x8821f65103cb8efa;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949bb0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * 0x2dfb217536b481cf + -0x7a92351b823eab9e;
        uVar23 = lVar16 * 0x435c45a731367c63 + 0xa03b7e8504b5f5a8;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949c30 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
         tempout =
            (uVar23 * -0x4d45091000000000 + lVar16 * 0x1fb13a25f4b76413) * -0x7c6486fc7cd2995 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x36a8897cbdf49a97;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a); //seems OK... CHECKED
    lVar12 = 0x349aaf26987d23b9;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x6ef073d6b49406f9 +
            lVar12 * 0x4e58fe03248faab5 + -0x7bf2b8a535e30dd2;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x1897fcf4085fb539 + 0x77cbc837b84ebc4d;
        *(longlong *)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949cb0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0xdfb585000000000 + *(longlong*)(&local_3150[56]) * 0x30d157e24f204a7b +
            -0x233cbd28f776ea76;
        *(int*)(local_d40 + lVar16 * 4-0x168)=
            ((int)*(longlong*)(&local_3150[56]) * -0x30000000 + (int)lVar7 * -0x78fbadfb + 0x1cc0d580) *
            *(int*)((longlong)DAT_180949d30 + uVar23 * 4) +
            *(int*)((longlong)DAT_180949d50 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    local_42e8 = *(longlong*)(local_42f0 + 0xf18); //good ?
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    uVar23 = 0; //local_d40 is off at 0
    do {
        lVar12 = 0x44d80b13747cea45;
        if (uVar23 < 0x5a) {
            uVar14 = (ulonglong)((int)uVar23 * 4 & 0x1c);
            uVar17 = (ulonglong)
                ((*(int*)(local_d40 + uVar23 * 4) * *(int*)((longlong)DAT_180949d70 + uVar14) +
                    *(int*)((longlong)DAT_180949d90 + uVar14)) * 0x5b256b2f + 0xa5ad0c9d);
            uVar14 = uVar17 * 0x6ad8b76beaa43021 + 0x66db85401b74faac;
            iVar9 = 8;
            do {
                uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_180949db0 + (ulonglong)((uint)uVar14 & 0xf) * 8)
                    ;
                iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
            lVar12 = uVar14 * -0x45112a6700000000 + uVar17 * 0x127f9816f25c747 + 0x5da5afcc16fac65;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4); //seems OK until 2 at least?
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(local_42f0 + lVar12 * 4 + 0xad8) *
                *(int*)((longlong)DAT_180949e30 + uVar23) +
                *(int*)((longlong)DAT_180949e50 + uVar23)) * 0x59231ba3 + 0xfd0f658d);
        uVar14 = uVar23 * -0x3d7cf3377f803cef + 0xf443fa92e91290c2;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_180949e70 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_4e0 + lVar12 * 8) =
            uVar14 * -0x2c85e6100000000 + uVar23 * 0x1779c3aa21512771 + -0x3f4a66b379bb644d;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);//seems OK... 
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 =tempout* ((longlong)local_42e8 * 0x514691bcd976da35 + 0x58fe7164e2075066) +
            (longlong)local_42e8 * -0x329900df6294249 + -0x522db4084fe026c8;
        uVar23 = lVar16 * 0xdcd85272f2e4dcb + 0x1d33c5acdbe0994;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949ef0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x35cea32eb0000000 + lVar16 * -0x60fdd9b795bef0a7 + -0x12ed90399bd40f20;
        lVar16 = lVar7 * 0x73e1b7db3b641dbf + -0x5bb2c5bb80dd505a;
        uVar23 = lVar7 * 0x55aa4bd51fdb5ab7 + 0x86dca2b2cde272d6;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);

        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_4e0 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_4e0 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            memcpy(xmm2.data, &local_4e0[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar20[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar20[lVar7 * 8], xmm2.data, 16);

            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x67cd8db41443c8d5 + 0x33ec45fb52a9b0f6;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949f70 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x65e9039e762fa2f5 + -0x1c5019b7b4fa5198;
        uVar23 = lVar16 * 0x79b9152b4f6cf8fd + 0x73c6fd0661228ef6;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_180949ff0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        tempout =
            (uVar23 * -0x3df8df9000000000 + lVar16 * 0x63ba553891848715) * -0x727982847e589305 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + -0x499fad726d299d31;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a); 
    lVar12 = -0x6a368e1c65d17955;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0x430334081f91f471 +
            lVar12 * -0x44ad0113b84af037 + -0x5ad097a3f1c5e401;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * 0x6aaad71902c11f83 + 0xd74949834a995c90;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a070 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x1217ead000000000 + *(longlong*)(&local_3150[56]) * -0x678ba075c1217ead +
            -0x3f87c877b8861984;
        local_32c0[lVar16-0x5a] =
            ((int)*(longlong*)(&local_3150[56]) * -0x30000000 + (int)lVar7 * 0x7358eb39 + 0x70d13b54) *
            *(int*)((longlong)DAT_18094a0f0 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094a110 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4); 
    Maybe_MEMSET_180512a50((char*)local_3430, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_2710, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_1e80, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_2b20, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50(local_1170, 0xaa, 0x2d0);
    pbVar27 = local_42f0;
    local_42d8 = *(byte**)(local_42f0 + 0xf20);
    pbVar20 = local_42f0 + 0x1230;
    pbVar21 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar21, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    piVar1 = local_42e0;
    Ecarrys_1801a68ef((byte*)local_42e0, 0, (longlong*)local_4e0);
    local_42e8 = (longlong)pbVar20;
    Ecarrys_1801a6991(pbVar20, 0, (longlong*)local_910);
    *(longlong*)local_1620 = *(longlong*) local_4e0;
    local_1a50[0] = *(longlong*)local_910;
    lVar16 = 1;
    lVar12 = 8;
    ulonglong tmpq= *(longlong*)local_4e0;
    do {
        Ecarrys_1801a68ef((byte*)piVar1, (uint)lVar16, (longlong*)(local_4e0 + lVar12));
        pbVar20 = (byte *) local_42e8;
        tmpq = tmpq + *(longlong*)(local_4e0 + lVar16 * 8);
        *(longlong*)(local_1620 + lVar16 * 8) = tmpq;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a);
    lVar16 = 1;
    lVar12 = 8;
    tmpq= *(longlong*)local_910;
    do {
        Ecarrys_1801a6991(pbVar20, (uint)lVar16, (longlong*)(local_910 + lVar12));
        tmpq = tmpq + *(longlong*)(local_910 + lVar16 * 8);
        local_1a50[lVar16] = tmpq;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a); 
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = 0x6aca5e4b6ffe5147;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + *(longlong*)(local_910 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_1620 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_1620 + (ulonglong)(uVar5 - 1) * 8);
            }
            uVar14 = local_1a50[uVar10 - uVar5];
            if (0x59 < uVar23) {
                uVar14 = uVar14 - local_1a50[~uVar25 + uVar10];
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0x8bbd7f66ebb3999 + 0x6aca5e4b6ffe5147 +
                lVar12 * 0x765354fbb8293d37 + lVar16 * 0x1fa0447e1b6aa1f3 +
                uVar14 * 0x476d1e7b9c5daf9b;
            pbVar27 = local_42f0;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * -0x35ae2d9c8d5ca67b + 0xfc8617042cf4d4d;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4); 
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(pbVar27 + lVar12 * 4 + 0x100) * *(int*)((longlong)DAT_18094a2b0 + uVar23)
                + *(int*)((longlong)DAT_18094a2d0 + uVar23)) * 0x399bf8f3 + 0xadb0442a);
        uVar14 = uVar23 * -0x257ccb1c53c9cb97 + 0x1b7ee887a0ce8bbb;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094a2f0 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_4e0 + lVar12 * 8) =
            uVar14 * 0x4eea19f700000000 + uVar23 * -0x7ffb0aea5964d24f + -0x257dbf2651452f9;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 = tempout* ((longlong)local_42d8 * -0x214f4978f6befe4b + 0x26c01b54433b4534) +
            (longlong)local_42d8 * 0x4464bd47dd558010 + 0x642e2cb050e5c668;
        uVar23 = lVar16 * -0x47dc434c44ca4685 + 0x26435711cc9a0ad2;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a370 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * 0x276fcce170000000 + lVar16 * 0x1fd7a76dabd75bf3 + 0x44ea69c918734acf;
        lVar7 = lVar16 * -0x7d96dc2b7fa406db + -0x70969c442a573bc3;
        uVar23 = lVar16 * -0x245d0ffd540f1369 + 0x6ca581c17ee9e69f;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar7);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar16 = 0;
        do {
            uVar14 = *(ulonglong*)(local_4e0 + lVar16 * 8);
            uVar17 = *(ulonglong*)(local_4e0 + lVar16 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar21 + lVar16 * 8) + 8);
            memcpy(xmm2.data, &local_4e0[lVar16 * 8], 16);
            memcpy(xmm3.data, &pbVar21[lVar16 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar21[lVar16 * 8], xmm2.data, 16);
            lVar16 = lVar16 + 2;
        } while (lVar16 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * -0x1f7785bc595f368b + 0x97c62846456cb907;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a3f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x14bfc64fadbd8531 + 0x69219e825c3f177b;
        uVar23 = lVar16 * -0x73be65153d9ef697 + 0x4811d4be9565812c;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a470 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
         tempout =
            (uVar23 * -0x2299423000000000 + lVar16 * -0x5690f58a8f7a02a5) * 0x3934029503e7e929 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x4130605c25ce70d4;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar21 = pbVar21 + 8;
    } while (lVar12 != 0x5a); 
    lVar12 = -0x41fe8c0acddef1e8;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x74208656d7d8c8af +
            lVar12 * 0x1983fe7c4e926e81 + -0x2682990fad701508;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        pbVar20 = local_42f0;
        uVar23 = lVar7 * 0x466f6c603b7bfdcd + 0x955ea67c1b6287ba;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a4f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong *)(&local_3150[128]) * -0x642ce85000000000 + *(longlong*)(&local_3150[56]) * -0x2590313d59bd317b +
            0x3cf7b41b13bfb436;
        *(int*)(local_2710+lVar16*4-0x168) =
            ((int)*(longlong*)(&local_3150[56]) * -0x50000000 + (int)lVar7 * 0x6d0eefd1 + 0x2655d227) *
            *(int*)((longlong)DAT_18094a570 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094a590 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    local_42e0 = *(int**)(local_42f0 + 0xf20);
    piVar1 = (int*)(local_42f0 + 0x2590);
    pbVar21 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar21, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    ECarry_6_1801a6a33(piVar1, 0, (longlong*)local_4e0);
    Ecarrys_1801a6ad5((byte *) local_42e8, 0, (longlong*)local_910);
    *(longlong *)local_1620 = *(longlong*)local_4e0;
    local_1a50[0] = *(longlong*)local_910;
    lVar16 = 1;
    lVar12 = 8;
    longlong tmpl= *(longlong*)local_4e0;
    do {
        ECarry_6_1801a6a33(piVar1, (uint)lVar16, (longlong*)(local_4e0 + lVar12));
        pbVar27 = (byte *) local_42e8;
        tmpl = tmpl + *(longlong*)(local_4e0 + lVar16 * 8);
        *(longlong*)(local_1620 + lVar16 * 8) = tmpl;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a);
    lVar16 = 1;//seems OK??
    lVar12 = 8;
    tmpl= *(longlong*)local_910;
    do {
        Ecarrys_1801a6ad5(pbVar27, (uint)lVar16, (longlong*)(local_910 + lVar12));
        tmpl = tmpl + *(longlong*)(local_910 + lVar16 * 8);
        local_1a50[lVar16] = tmpl;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a);
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = -0x25892680caf42d7e;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + *(longlong*)(local_910 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_1620 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_1620 + (ulonglong)(uVar5 - 1) * 8);
            }
            uVar14 = local_1a50[uVar10 - uVar5];
            if (0x59 < uVar23) {
                uVar14 = uVar14 - local_1a50[~uVar25 + uVar10];
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0x48ab2777d91ac2d0 + -0x25892680caf42d7e +
                lVar12 * 0x533ab0f8be2ffb39 + lVar16 * -0x512a8518f6c064d2 +
                uVar14 * -0x54ad7addee7aee18;
            pbVar20 = local_42f0;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * 0x4f85d7cd854e49db + -0x5bd40c28101f71d7;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(pbVar20 + lVar12 * 4 + 0x100) * *(int*)((longlong)DAT_18094a730 + uVar23)
                + *(int*)((longlong)DAT_18094a750 + uVar23)) * -0x363e5fc9 + 0x40a1ca79);
        uVar14 = uVar23 * 0x477e41495a0f1d23 + 0x4dda3829199b98f9;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094a770 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_4e0 + lVar12 * 8) =
            uVar14 * -0x2dd500dd00000000 + uVar23 * -0x1b388b4bdbd4d8c9 + -0x5028235baa7d911e;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 =tempout* ((longlong)local_42e0 * 0x2c900d457201b45 + -0x52232b28d485f68c) +
            (longlong)local_42e0 * -0x260d70ab2451e79b + -0x33d4977691400514;
        uVar23 = lVar16 * 0x2266c0b34ba2cfc3 + 0x952bf38cd9f25e6;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a7f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x7b1be107f0000000 + lVar16 * -0x62a5ef724784be43 + -0x3d9a03e256975629;
        lVar16 = lVar7 * 0x2ff4b5a7c661974f + 0x47a589c2285f153f;
        uVar23 = lVar7 * -0x1743b4bc9b6e10e3 + 0x4513ffeaf2534bed;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_4e0 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_4e0 + lVar7 * 8 + 8);
            memcpy(xmm2.data, &local_4e0[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar21[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar21[lVar7 * 8], xmm2.data, 16);
            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x490cc14f7aadfc5b + 0xcf8ddc448f741111;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a870 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * 0x44ffa8d86f3d2a51 + 0x2cb298ca01fc214a;
        uVar23 = lVar16 * 0x1bb08b803f107647 + 0x23116398ad2c8485;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a8f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        tempout =
            (uVar23 * -0x577f43f000000000 + lVar16 * 0x3fcecce723c9c779) * 0x29903a011287263b +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x7f0aaafcb4e2165d;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar21 = pbVar21 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = -0x3f11fba36fdfe4fa;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0x3a8aef76e309c5d5 +
            lVar12 * 0x6ef004372b51ead3 + -0x1d66cf65c94d37c1;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * 0x71f81ffb183d88fd + 0xf145c9030da6bc39;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094a970 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x78384c9000000000 + *(longlong*)(&local_3150[56]) * -0x40bf94d8578384c9 +
            0x45c388774cb9c773;
        local_1e80[lVar16-0x5a] =
            ((int)*(longlong*)(&local_3150[56]) * -0x30000000 + (int)lVar7 * -0x293fdab9 + 0x6a60154b) *
            *(int*)((longlong)DAT_18094a9f0 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094aa10 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4); 
    Maybe_MEMSET_180512a50((char*)local_22b0, 0xaa, 0x168);
    lVar12 = 0;
    do {
        *(int*)(local_22b0 + lVar12 * 4) =
            *(int*)((longlong)DAT_18094aa30 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    do {
        *(int*)(local_22b0 + lVar12 * 4) =
            *(int*)(local_22b0 + lVar12 * 4) +
            local_32c0[lVar12] * *(int*)((longlong)DAT_18094aa50 + (ulonglong)((uint)lVar12 & 7) * 4)
            ;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    do {
        *(int*)(local_22b0 + lVar12 * 4) =
            *(int*)(local_22b0 + lVar12 * 4) +
            *(int*)(local_42f0 + lVar12 * 4 + 0x100) *
            *(int*)((longlong)DAT_18094aa70 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    memcpy(xmm0.data, local_42c0, 16);
    {
        unsigned char dt[16] = {0x77,0x5f,0xa4,0xf5, 0xe5,0x9e,0xf4,0xc2, 0x33,0x67,0x47,0x92, 0xad, 0x62, 0xb3,0xd5};
        memcpy(xmm1.data, dt, 16);
    }
    xmm2.PSHUFD(xmm0, 0xf5);
    xmm0.PMULUDQ(xmm1);
    xmm0.PSHUFD(xmm0, 0xe8);
    xmm1.PSHUFD(xmm1, 0xf5);
    xmm1.PMULUDQ(xmm2);
    xmm1.PSHUFD(xmm1, 0xe8);
    xmm0.PUNPCKLDQ(xmm1);
    memcpy(tmp.data, local_22b0, 16);
    xmm0.PADDD(tmp);
    memcpy(local_22b0, xmm0.data,16);

    lVar12 = 4;
    do {
        *(int*)(local_22b0 + lVar12 * 4) =
            *(int*)(local_22b0 + lVar12 * 4) +
            *(int*)(DAT_18094aa90 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    iVar9 = 0x2c0d8c79;
    lVar12 = 0;
    do {
        iVar11 = iVar9 * -0x46b39d05 + *(int*)(local_22b0 + lVar12 * 4);
        uVar10 = iVar11 * 0x1df89a7f + 0x3d03375e;
        *(int*)local_1620=  uVar10;
        lVar16 = 0;
        do {
            uVar10 = (uVar10 >> 4) + *(int*)(DAT_18094aab0 + (ulonglong)(uVar10 & 0xf) * 4);
            *(uint*)(local_1620 + lVar16 * 4 + 4) = uVar10;
            lVar16 = lVar16 + 1;
        } while (lVar16 != 8);
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        iVar9 = *(int *)(&local_1620[28]) * 0x4f70204d + *(int*)(&local_1620[32]) * 0x8fdfb30 + -0x2b495b31;
        *(int*)(local_2b20 + lVar12 * 4) =
            (iVar11 * 0x39507639 + *(int*)(&local_1620[28]) * -0x70000000 + 0x706f80f8) *
            *(int*)((longlong)DAT_18094aaf0 + uVar23) + *(int*)((longlong)DAT_18094ab10 + uVar23);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x2d8);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d8);
    lVar12 = 0;
    *(ulonglong*)local_30c0=0;
    *(ulonglong*)local_1620 = 0;
    lVar16 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar16 * 4 & 0x1c);
        uVar14 = (ulonglong)
            ((local_1e80[lVar16] * *(int*)((longlong)DAT_18094ab30 + uVar23) +
                *(int*)((longlong)DAT_18094ab50 + uVar23)) * -0x5f220a05 + 0xdcaa977d);
        uVar23 = uVar14 * -0x238493842de67223 + 0x66ed1226a32a07f2;
        iVar9 = 8;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094ab70 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * 0x4128a300000000 + uVar14 * -0x6001c212c98cdbb7 + 0x4ea782762934f1cd;
        *(longlong*)(local_4e0 + lVar16 * 8) = lVar7;
        lVar12 = lVar12 + lVar7;
        *(longlong*)(local_30c0 + lVar16 * 8 + 8) = lVar12;
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0x5a);
    lVar12 = 0;
    lVar16 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar16 * 4 & 0x1c);
        uVar14 = (ulonglong)
            ((*(int*)(local_2b20 + lVar16 * 4) * *(int*)((longlong)DAT_18094abf0 + uVar23) +
                *(int*)((longlong)DAT_18094ac10 + uVar23)) * -0x59d60979 + 0xed1035b3);
        uVar23 = uVar14 * -0x7b92100d61214761 + 0xdb47cf17275cb54a;
        iVar9 = 8;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094ac30 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x515a522900000000 + uVar14 * 0x70f0982effb47f77 + -0x715166de604dc292;
        *(longlong*)(local_910 + lVar16 * 8) = lVar7;
        lVar12 = lVar12 + lVar7;
        *(longlong*)(local_1620 + lVar16 * 8 + 8) = lVar12;
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0x5a); 
    lVar12 = 0x30db04b7ec7191b3;
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar25 = uVar10 - 0x59;
        if (uVar10 < 0x59) {
            uVar25 = 0;
        }
        uVar5 = (uint)uVar14;
        if (uVar25 <= uVar5) {
            uVar24 = (ulonglong)uVar25;
            uVar13 = uVar23 - uVar24;
            lVar16 = 0;
            uVar17 = uVar24;
            do {
                lVar16 = lVar16 + *(longlong*)(local_910 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar7 = *(longlong*)(local_1620 + (ulonglong)((uVar10 - uVar25) + 1) * 8);
            if (0x59 < uVar23) {
                lVar7 = lVar7 - *(longlong*)(local_1620 + (ulonglong)(uVar10 - uVar5) * 8);
            }
            lVar12 = (ulonglong)((uVar5 - uVar25) + 1) * 0x57bb551f4517a7d5 + lVar12 +
                lVar16 * 0x1f68cbb1cf55f54f +
                (*(longlong*)(local_30c0 + uVar14 * 8 + 8) - *(longlong*)(local_30c0 + uVar24 * 8))
                * -0x767c70aa36047243 + lVar7 * -0x417a507847245d29;
        }
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar14 = lVar12 * -0x7da469bb627586b3 + 0x5a1912a84edf2f63;
        *(ulonglong*)local_3150 = uVar23;
        lVar16 = 0;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094acb0 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar16 * 8 + 8) = uVar14;
            lVar16 = lVar16 + 1;
        } while (lVar16 != 0x10);
        iVar9 = (int)lVar12;
        uVar14 = (ulonglong)(uVar10 * 4 & 0x1c);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x73a987b000000000 + *(longlong*)(&local_3150[56]) * -0x69667d43873a987b +
            0x5e2886495acc8c91;
        *(int*)(local_d40 + uVar23 * 4) =
            ((int)*(longlong*)(&local_3150[56]) * 0x30000000 + iVar9 * -0x497cb7f7 + 0x60f738d1) *
            *(int*)((longlong)DAT_18094ad30 + uVar14) + *(int*)((longlong)DAT_18094ad50 + uVar14);
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        *(undefined4*)(local_30c0 + lVar12 * 4) =
            *(undefined4*)((longlong)DAT_18094ad70 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    lVar12 = 0;
    do {
        *(int*)(local_30c0 + lVar12 * 4) =
            *(int*)(local_30c0 + lVar12 * 4) +
            *(int*)(local_d40 + lVar12 * 4) *
            *(int*)((longlong)DAT_18094ad90 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    lVar12 = 0;
    do {
        *(int*)(local_30c0 + lVar12 * 4) =
            *(int*)(local_30c0 + lVar12 * 4) +
            *(int*)(local_2710 + lVar12 * 4) *
            *(int*)((longlong)DAT_18094adb0 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a); 
    lVar12 = 0x5a;
    do {
        *(int*)(local_30c0 + lVar12 * 4) =
            *(int*)(local_30c0 + lVar12 * 4) +
            *(int*)(DAT_18094add0 + (ulonglong)((uint)lVar12 & 7) * 4);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    iVar9 = -0x26c90d79;
    lVar12 = 0;
    do {
        iVar11 = iVar9 * -0x3a494f61 + *(int*)(local_30c0 + lVar12 * 4);
        uVar10 = iVar11 * -0x38a59e8f + 0xb6fdb647;
        *(uint*)local_1620 =  uVar10;
        lVar16 = 0;
        do {
            uVar10 = (uVar10 >> 4) + *(int*)(DAT_18094adf0 + (ulonglong)(uVar10 & 0xf) * 4);
            *(uint*)(local_1620 + lVar16 * 4 + 4) = uVar10;
            lVar16 = lVar16 + 1;
        } while (lVar16 != 8);
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        iVar9 = *(uint*)&local_1620[28] * 0xf5331cf + *(uint*)&local_1620[32] * 0xacce310 + -0x4c3b9843;
        *(int*)(local_1170 + lVar12 * 4) =
            (iVar11 * 0x53f3b609 + *(uint*)&local_1620[28] * 0x70000000 + 0x5890cdf6) *
            *(int*)((longlong)DAT_18094ae30 + uVar23) + *(int*)((longlong)DAT_18094ae50 + uVar23);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    lVar12 = *(longlong*)(local_42f0 + 0xf20);
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    lVar16 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar16 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(local_1170 + lVar16 * 4) * *(int*)((longlong)DAT_18094ae70 + uVar23) +
                *(int*)((longlong)DAT_18094ae90 + uVar23)) * 0x2bc793cf + 0xd5da9dc1);
        uVar14 = uVar23 * -0x47f412bc0a8b3687 + 0xd26dfe8f531aff2a;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094aeb0 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_30c0 + lVar16 * 8) =
            uVar14 * -0x256a0a1b00000000 + uVar23 * -0x2df2af44a3b6063d + -0x5bd0aa4b6733d65;
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    lVar16 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar16 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)(local_42f0 + lVar16 * 4 + 0x100) *
                *(int*)((longlong)DAT_18094af30 + uVar23) +
                *(int*)((longlong)DAT_18094af50 + uVar23)) * 0x231cf84f + 0x9dd7a96d);
        uVar14 = uVar23 * -0x5378840055eb4143 + 0x99f323e96e3e49c3;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094af70 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_4e0 + lVar16 * 8) =
            uVar14 * -0x326d8c2b00000000 + uVar23 * 0x1b4eaa1f0a4465bf + -0x2dd1d57e8e212f30;
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0x5a); 
    lVar16 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar7 = tempout* (lVar12 * 0x4c1dbc6ef8dc00e7 + -0x1c922fb36807f244) +
            lVar12 * -0x1bcc3bbf6e7555ed + -0x6a4eac422c4a146e;
        uVar23 = lVar7 * -0x606a3bdc357b3d17 + 0x26a4abba34ec86d2;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094aff0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar18 = uVar23 * -0x6d915563f0000000 + lVar7 * -0x6e67917711bcc2a9 + 0x3336701cfe318679;
        lVar7 = lVar18 * 0x7259038902a91ee0 + 0x204228bc5b1cdf60;
        uVar23 = lVar18 * 0x43f4cc8823b73f95 + 0x24947e3b63918ce1;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar7);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar18 = 0;
        do {
            uVar14 = *(ulonglong*)(local_4e0 + lVar18 * 8);
            uVar17 = *(ulonglong*)(local_4e0 + lVar18 * 8 + 8);
            lVar3 = *(longlong*)((longlong)(pbVar20 + lVar18 * 8) + 8);
            memcpy(xmm2.data, &local_4e0[lVar18 * 8], 16);
            memcpy(xmm3.data, &pbVar20[lVar18 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar20[lVar18 * 8], xmm2.data, 16);
            lVar18 = lVar18 + 2;
        } while (lVar18 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x356b4b06efa204c7 + 0xac8ee867cc097f5e;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b070 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x7d8e9c76bc2d8739 + 0x2a05a84c7bfb9c62;
        uVar23 = lVar7 * 0x50b69fc7802e9e7d + 0x6e6440b7075f80b2;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b0f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
       tempout =
            (uVar23 * 0x74988cd000000000 + lVar7 * 0x73ede9629d3ade7) * 0x5479fab77cf830f9 +
            *(longlong*)(local_30c0 + lVar16 * 8 + 8) + 0x628abd7acdb42d4d;
        *(longlong*)(local_30c0 + lVar16 * 8 + 8) = tempout;
        lVar16 = lVar16 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar16 != 0x5a);
    lVar12 = -0x3e2f61bb2ff09623;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x4fd83d19df00ede3 +
            lVar12 * 0x7a6ac0f467bea60d + -0x40bfc36ee83feaa1;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x2458cc5404fe59d7 + 0xe3bfaf1489801715;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b170 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x76566c3000000000 + *(longlong*)(&local_3150[56]) * -0x41fda6c8a76566c3 +
            -0x6a94eef9d12bb697;
        local_3430[lVar16-0x5a] =
            ((int)*(longlong*)(&local_3150[56]) * -0x50000000 + (int)lVar7 * -0x14b7f7f3 + -0x63802412) *
            *(int*)((longlong)DAT_18094b1f0 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094b210 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_3840, 0xaa, 0x403);
    pbVar20 = local_42f0;
    memcpy(local_3940, local_42f0, 0x100);
    *(short *)local_2b20 =  0x203;
    bVar19 = 0;
    Maybe_MEMSET_180512a50((char*)(local_2b20 + 2), 0, 0x401);
    uVar23 = 0;
    do {
        local_2b20[uVar23 + 2] =
            *(byte*)((longlong)local_3940 + ((uVar23 & 0xffffffff) >> 2)) >> (bVar19 & 6) & 3;
        uVar23 = uVar23 + 1;
        bVar19 = bVar19 + 2;
    } while (uVar23 != 0x400);
    ConstUser_18016b077(0x40300001bbc0, local_2b20, local_2b20, local_3840);
    Maybe_MEMSET_180512a50((char*)local_3a80, 0xaa, 0x138);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        local_3a80[lVar12] =
            local_3430[lVar12] * *(int*)((longlong)DAT_18094b230 + uVar23) +
            *(int*)((longlong)DAT_18094b250 + uVar23);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x4e);
    Maybe_MEMSET_180512a50((char*)local_3e88, 0xaa, 0x402);
    *(longlong*)(&local_4290[7]) = 0x201000405020004;
    *(longlong*)local_4290 = 0x402050101040605;
    local_42e8 = *(longlong*)(pbVar20 + 0xf50);
    local_42d0 = (int*)(pbVar20 + 0x1668);
    Maybe_MEMSET_180512a50((char*)local_1e80, 0xaa, 0x425);
    Maybe_MEMSET_180512a50((char*)local_22b0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x168);
    pbVar21 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar21, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x270);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x270);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    Ecarrys_1801a6b77(local_3a80, 0, (longlong*)local_4e0);
    Ecarrys_1801a6c19((int*)(pbVar20 + 0x1398), 0, (longlong*)local_1620);
    *(longlong*)local_910 = *(longlong*)local_4e0;
    *(longlong*)local_1a50= *(longlong*)local_1620;
    lVar12 = 1;
    lVar16 = 8;
     tmpl= *(longlong*)local_4e0;
    do {
        Ecarrys_1801a6b77(local_3a80, (uint)lVar12, (longlong*)(local_4e0 + lVar16));
        tmpl = tmpl + *(longlong*)(local_4e0 + lVar12 * 8);
        *(longlong*)(local_910 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x4e);
    local_42e0 = (int*)(local_42f0 + 0xc40); 
    local_42d8 = local_42f0 + 0xf28;
    lVar12 = 1;
    lVar16 = 8;
    tmpl = *(longlong* )local_1620;
    do {
        Ecarrys_1801a6c19((int*)(pbVar20 + 0x1398), (uint)lVar12, (longlong*)(local_1620 + lVar16));
       tmpl = tmpl + *(longlong*)(local_1620 + lVar12 * 8);
        local_1a50[lVar12] = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    uVar23 = 0;
    do {
        uVar14 = 0x4d;
        if (uVar23 < 0x4d) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = 0x1249d72ecc183321;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + *(longlong*)(local_1620 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_910 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_910 + (ulonglong)(uVar5 - 1) * 8);
            }
            uVar14 = local_1a50[uVar10 - uVar5];
            if (0x4d < uVar23) {
                uVar14 = uVar14 - local_1a50[~uVar25 + uVar10];
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0x3d56c4b37a9e4d1c + 0x1249d72ecc183321 +
                lVar12 * 0x713bf74e799c5529 + lVar16 * 0x398e0401b01380fc +
                uVar14 * -0x6e56ac5ba6636ee1;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * -0xaf293f1ab527461 + -0x266bb07bf49aa283;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4); 
    memcpy(local_1a50, (byte*)local_42e0, 0x168);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 =(uint)
            ((*(int*)((longlong)local_1a50 + lVar12 * 4) *
                *(int*)((longlong)DAT_18094b3f0 + uVar23) +
                *(int*)((longlong)DAT_18094b410 + uVar23)) * 0x3c3f1a4b + 0x6ba3a855);
        uVar14 = uVar23 * 0x711fd26eba0518e5 + 0x992499da19a651a3;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094b430 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_1620 + lVar12 * 8) =
            uVar14 * 0x27b3c7e100000000 + uVar23 * -0x51ce4827bff3e445 + -0x7111e6e2cb20d24b;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 = tempout* ((longlong)local_42e8 * 0x3648b59280e71661 + 0x1463dd44f5e73707) +
            (longlong)local_42e8 * -0x56b1410b63a0707c + -0x32c1a01092b3cf6f;
        uVar23 = lVar16 * -0x7fa6bcc4333a345d + 0x504366a62d3dd266;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b4b0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x7e2361baf0000000 + lVar16 * -0x5ea75da24ded9a93 + 0x2c5769f6acadce06;
        lVar16 = lVar7 * 0x29c550da25a185f9 + -0x50f9520e418f6e1f;
        uVar23 = lVar7 * -0x722cc4957bd5a595 + 0xbfae8741a3895223;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_1620 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_1620 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar21 + lVar7 * 8) + 8);
            memcpy(xmm2.data, &local_1620[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar21[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar21[lVar7 * 8], xmm2.data, 16);

            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * -0x2be06bca0e3134d5 + 0x647a9f5da57993f5;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b530 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x12a90a2bfb5517b1 + 0xd12a6d8707f0462;
        uVar23 = lVar16 * 0x425385b198d6513d + 0x82f8df886ec5817;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b5b0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
       tempout =
            (uVar23 * 0x565f015000000000 + lVar16 * 0x29049897ec3125ff) * 0x4bbb9bc764763973 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x14f423becf340acc;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar21 = pbVar21 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = -0x5534355aee8d375b;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0x477c05c3ddf4f22f +
            lVar12 * 0x6a377e025922a59d + -0x22bfb38718fe2223;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * 0x595fc6edf32ce41f + 0x5f59b62c267fb0f1;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b630 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * -0x16358ab000000000 + *(longlong*)(&local_3150[56]) * 0x4759a769716358ab +
            0x4480fb240bdb0b0;
       *(int*)(&local_22b0[lVar16*4-0x168]) =
            ((int)*(longlong*)(&local_3150[56]) * -0x30000000 + (int)lVar7 * -0x2fee3c53 + 0x1f21f8e1) *
            *(int*)((longlong)DAT_18094b6b0 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094b6d0 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Ecarrys_1801a6cbb((int*)local_22b0, 0, (longlong*)local_1620);
    ECarrys_1801a6d5d(local_42d0, 0, (longlong*)local_1a50);
    *(longlong*)local_4e0 = *(longlong*) local_1620;
    *(longlong*) local_910 =  local_1a50[0];
    lVar16 = 1;
    lVar12 = 8;
    tmpl = *(longlong*)local_1620;
    do {
        Ecarrys_1801a6cbb((int*)local_22b0, (uint)lVar16, (longlong*)(local_1620 + lVar12));
        piVar1 = local_42d0;
        tmpl= tmpl+ *(longlong*)(local_1620 + lVar16 * 8);
        *(ulonglong*)(local_4e0 + lVar16 * 8) =tmpl;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a);
    lVar12 = 1;
    lVar16 = 8;
    tmpl = local_1a50[0];
    do {
        ECarrys_1801a6d5d(piVar1, (uint)lVar12, (longlong*)((longlong)local_1a50 + lVar16));
        tmpl = tmpl + local_1a50[lVar12];
        *(ulonglong*)(local_910 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a); 
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = -0x33c508b75d60932e;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + local_1a50[uVar13 & 0xffffffff] * *(longlong*)(local_1620 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_4e0 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_4e0 + (ulonglong)(uVar5 - 1) * 8);
            }
            lVar7 = *(longlong*)(local_910 + (ulonglong)(uVar10 - uVar5) * 8);
            if (0x59 < uVar23) {
                lVar7 = lVar7 - *(longlong*)(local_910 + (ulonglong)(~uVar25 + uVar10) * 8);
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * -0x39ae13a8ffd6bfa6 + -0x33c508b75d60932e +
                lVar12 * -0x442d2818833f7d69 + lVar16 * 0x452637a007461962 +
                lVar7 * -0x133a2a8e8eb12c05;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * -0x3ed7faf4c08ad92b + 0x8a69c8f1af90e9b;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4);
    memcpy(local_1a50, (byte*)local_42e0, 0x168);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)((longlong)local_1a50 + lVar12 * 4) *
                *(int*)((longlong)DAT_18094b870 + uVar23) +
                *(int*)((longlong)DAT_18094b890 + uVar23)) * -0x3d03644b + 0x57500016);
        uVar14 = uVar23 * 0x5d66497919e347d3 + 0x29cb2f025e4f97c;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094b8b0 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_1620 + lVar12 * 8) =
            uVar14 * -0x239bbe4f00000000 + uVar23 * -0x2fcaa325fdcd3be3 + 0x66a9c969452ab995;
        lVar12 = lVar12 + 1; 
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 = tempout * ((longlong)local_42e8 * 0x33033e710be1afa9 + 0x3bd53b8e3e6612ff) +
            (longlong)local_42e8 * -0x1670a5813233601d + -0x3036a8884a63b498;
        uVar23 = lVar16 * -0x6eaaf8980a1af877 + 0xf177b35db7e5f93e;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b930 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * 0x503d306c10000000 + lVar16 * 0x644cb2d36f3d1bb7 + -0x7f7d5c5e8fd6ced4;
        lVar16 = lVar7 * 0x1975c5f03ae37c49 + 0x7e7ba0e453e83af7;
        uVar23 = lVar7 * 0x6b255d9f91918b05 + 0xcc23baa4d25ba73b;

        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_1620 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_1620 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            memcpy(xmm2.data, &local_1620[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar20[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar20[lVar7 * 8], xmm2.data, 16);

            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * -0x49f3ead73942285d + 0x1007f6bce8c37d4e;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094b9b0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x52d07414d406a37 + 0x23c56382a180c81f;
        uVar23 = lVar16 * -0x408c570b6a8dad5b + 0x787a0f4d1cc57756;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094ba30 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        tempout=
            (uVar23 * 0x4d1934b000000000 + lVar16 * 0x5f30c85a75580aa9) * 0x61eddd339b37c67b +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + -0x52f8375a86aa8322;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = 0x2c003dfc99c33c9;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x718377e7b76092c1 +
            lVar12 * 0x511c5cc37ecf511b + -0x50631d6330555bc;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x5e868ba96945f399 + 0x53f5128f97047074;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094bab0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x6a3658b000000000 + *(longlong*)(&local_3150[56]) * -0x2b11e68476a3658b +
            -0x5992d7846830b081;
        *(int*)(local_d40 + lVar16 * 4 - 0x168) =
            ((int)*(longlong*)(&local_3150[56]) * 0x70000000 + (int)lVar7 * -0xd967cf1 + -0x7bdde559) *
            *(int*)((longlong)DAT_18094bb30 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094bb50 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x4c0);
    lVar12 = 0;
    uVar34 = 0x2070600;
    uVar35 = 0x60600;
    uVar37 = 0x1070705;
    uVar38 = 0x7030101;
    {
        unsigned char dt[16] = {0,6,7,2,0,6,6,0,5,7,7,1,1,1,3,7};
        memcpy(xmm7.data, dt, 16);
    }
    do {
        uVar10 = *(uint*)(local_d40 + lVar12 * 4);
        lVar16 = 0;
        do {
            *(char*)((longlong)local_42a0 + lVar16) = (char)uVar10;
            uVar25 = local_42a0[0];
            uVar10 = uVar10 >> 8;
            lVar16 = lVar16 + 1;
        } while (lVar16 != 4);
        local_42a0[0] = local_42a0[0] & 0xfffffff;
        *(uint*)local_1620 = local_42a0[0]; 
        *(short *)local_2b20= 4;
        bVar19 = 0;
        *(longlong*)(&local_2b20[8]) = 0;
        *(longlong*)(&local_2b20[2]) = 0;
        uVar23 = 0;
        do {
            local_2b20[uVar23 + 2] = local_1620[(uVar23 & 0xffffffff) >> 2] >> (bVar19 & 6) & 3;
            uVar23 = uVar23 + 1;
            bVar19 = bVar19 + 2;
        } while (uVar23 != 0xe);
        ConstUser_18016b077(0x1000000ff38, local_2b20, local_2b20, local_3150);
        local_42e0 = (int*)((ulonglong)((uint)lVar12 & 7) * 0x10);
        pbVar20 = (byte*)((longlong)local_42e0 + DAT_18094bb70);
        memcpy(local_1a50, xmm7.data, 16);
        local_42e8 = lVar12;
        ConstUser_18016b077(0x100000105ee, local_3150, local_3150, local_2b20);
        ConstUser_18016b077(0x1000000a683, pbVar20, pbVar20, local_1620);
        ConstUser_18016b077(0x1000000946d, local_2b20, local_2b20, local_4e0);
        iVar9 = 0x1c;
        do {
            ConstUser_18016b077(0x10000027b6b, local_1620, (byte*)local_1a50, local_910);
            PFUN_180119595((uint*)DAT_18094bc80, (uint*)DAT_181443b64, 4, 0x5f19c9c7);
            ConstUser_18016b077(0x100000031d0, DAT_181443b64, local_910, local_1170);
            ConstUser_18016b077(0x1000000fbcb, local_2b20, local_1170, local_2710);
            ConstUser_18016b077(0x1000002e42a, local_4e0, local_2710, local_4e0);
            ConstUser_18016b077(0x1000000c838, local_2b20, local_2b20, local_2b20);
            ConstUser_18016b077(0x1000001f81d, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        ConstUser_18016b077(0x100000306f9, local_4e0, local_2b20, local_22e0);
        lVar12 = (longlong)local_42e8;
        ConstUser_18016b077(0x10000029b7a, local_22e0, (byte*)((longlong)local_42e0 + DAT_18094bbf0),
            local_30c0 + (longlong)local_42e8 * 0x10);
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x4c);
    ConstUser_18016b077(0x10000011480, local_30c0, local_30c0, local_2b20); //looks fine? 
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x4b0);
    lVar12 = 0;
    do {
        ConstUser_18016b077(0x1000002cd5a, local_30c0 + lVar12 + 0x10, local_30c0 + lVar12 + 0x10,
            local_1620 + lVar12);
        lVar12 = lVar12 + 0x10;
    } while (lVar12 != 0x4b0);
    puVar22 = local_1a50 + 2;
    Maybe_MEMSET_180512a50((char*)puVar22, 0xaa, 0x41a);
    memcpy(local_1a50,local_2b20,16);
    lVar12 = 2;
    do {
        uVar23 = *(ulonglong*)(local_1620 + lVar12);
        *(undefined8*)((longlong)puVar22 + 6) = *(undefined8*)(local_1620 + lVar12 + 6);
        *puVar22 = uVar23;
        puVar22 = (ulonglong*)((longlong)puVar22 + 0xe);
        lVar12 = lVar12 + 0x10;
    } while (lVar12 != 0x4b2);
    ConstUser_18016b077(0x4250000394cd, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1e80);
    Maybe_MEMSET_180512a50((char*)local_22b0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x426);
    memcpy(local_1a50, DAT_18094bc90, 0x426);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x426);
    OtherConstUser_180169484(0x4425000011025, (byte*)local_1e80, (byte*)local_1e80, local_30c0);
    OtherConstUser_180169484(0x105c00f00001ce1d, (byte*)local_4290, (byte*)local_4290, local_1620);
    ConstUser_18016b077(0x426000030c30, local_30c0, local_30c0, local_4e0);
    iVar9 = 0x1a;
    do {
        Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x426);
        Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x426);
        Maybe_MEMSET_180512a50(local_1170, 0xaa, 0x426);
        ConstUser_18016b077(0x426000029bde, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094c0c0, (uint*)DAT_181443b78, 0x10a, 0x5e8138ec);
        ConstUser_18016b077(0x42600000cad7, DAT_181443b78, local_910, local_d40);
        ConstUser_18016b077(0x4260000175ff, local_30c0, local_d40, local_1170); 
        ConstUser_18016b077(0x42600002a69a, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x426000038b97, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x42600000b3d8, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar9 = iVar9 + -1;
    } while (iVar9 != 0); 
    ConstUser_18016b077(0x426000011503, local_4e0, local_30c0, local_22b0);
    Maybe_MEMSET_180512a50((char*)local_2b20, 0xaa, 0x403);
    ConstUser_18016b077(0x250000205a3, local_22b0, local_22b0, local_3150);
    {
        unsigned char dt [16]= {3,3,7,1,3,3,7,1,7,7,2,6,4,6,4,4};
        memcpy(xmm0.data, dt,16);
    }
    memcpy(&local_1a50[2], xmm0.data, 16);
    {
        unsigned char dt[16] = { 1,3,7,2,4,0,5,7,3,3,3,2,4,5,1,1 };
        memcpy(xmm0.data, dt,16);
    }
    memcpy(&local_1a50[0], xmm0.data, 16);
    *(longlong*)(&((byte*)local_1a50)[29]) = 0x301050400040406;

    ConstUser_18016b077(0x2500001f93e, local_42d8, local_42d8, local_30c0);
    ConstUser_18016b077(0x2500002fc19, local_3150, local_3150, local_1620);
    ConstUser_18016b077(0x25000001685, local_30c0, local_30c0, local_4e0);
    iVar9 = 0x46;
    do {

        ConstUser_18016b077(0x25000023b5a, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094c520, (uint*)DAT_181443fa4, 10, 0x1b28e553);
        ConstUser_18016b077(0x250000353a1, DAT_181443fa4, local_910, local_d40);
        ConstUser_18016b077(0x25000006297, local_30c0, local_d40, local_1170);
        ConstUser_18016b077(0x2500000162d, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x25000027423, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x2500001c27c, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    ConstUser_18016b077(0x25000035d54, local_4e0, local_30c0, local_22e0);
    Maybe_MEMSET_180512a50((char*)local_2710, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x426);
    memcpy(local_1a50, DAT_18094c550, 0x426);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x426);
    OtherConstUser_180169484(0x8c40300001def6, local_3840, local_3840, local_30c0);
    OtherConstUser_180169484(0x1004025000002429, local_22e0, local_22e0, local_1620);
    ConstUser_18016b077(0x42600001625b, local_30c0, local_30c0, local_4e0);
    iVar9 = 0x46;
    do {
        Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x426);
        Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x426);
        Maybe_MEMSET_180512a50(local_1170, 0xaa, 0x426);
        ConstUser_18016b077(0x4260000291cb, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094c980, (uint*)DAT_181443fd0, 0x10a, 0xde8bf8a7);
        ConstUser_18016b077(0x42600000c409, DAT_181443fd0, local_910, local_d40);
        ConstUser_18016b077(0x42600002db54, local_30c0, local_d40, local_1170);
        ConstUser_18016b077(0x426000017f29, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x42600003592e, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x42600000502b, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    ConstUser_18016b077(0x4260000005b4, local_4e0, local_30c0, local_2710);  
    ConstUser_18016b077(0x426000037c8e, local_2710, local_22b0, local_2710); 
    OtherConstUser_180169484(0x403008c156f7, local_2710, local_2710, local_2b20);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x404);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x404);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x404);
    MB_Zeropad_180113d26(0x2018, local_2b20, 0x2020, local_30c0);
    MB_Zeropad_180113d26(0x2018, local_3840, 0x2020, local_1620);
    local_1620[1027] = 6;
    local_30c0[1027] = 4;
    ConstUser_18016b077(0x404000018c86, local_30c0, local_1620, (byte*)local_1a50);
    if (((byte*)local_1a50)[0x403] == '\x01') {
        uVar23 = 0x40200002b5f4;
        pbVar20 = local_2b20;
    }
    else {
        pbVar20 = local_30c0;
        Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x403);
        ConstUser_18016b077(0x403000031ea2, local_2b20, local_3840, pbVar20);
        uVar23 = 0x402000003d72;
    }
    ConstUser_18016b077(uVar23, pbVar20, pbVar20, local_3e88);
    pbVar21 = local_42f0;
    Maybe_MEMSET_180512a50((char*)&local_4290, 0xaa, 0x402);
    *(longlong*)(&((byte*)local_42a0)[7]) = 0x302050306050203;
    *(longlong*)(&((byte*)local_42a0)[0]) = 0x304060502050400;
    local_42e8 = *(longlong*)(pbVar21 + 0xf58);
    local_42e0 = (int*)(pbVar21 + 0xda8);
    Maybe_MEMSET_180512a50((char*)local_1e80, 0xaa, 0x425);
    Maybe_MEMSET_180512a50((char*)local_22b0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x168);
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x270);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x270);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    Ecarrys_1801a6dff(local_3a80, 0, (longlong*)local_4e0);
    Ecarrys_1801a6ea1(pbVar21 + 0x1500, 0, (longlong*)local_1620);
    *(longlong*)local_910 = *(longlong*) local_4e0;
    *(longlong*)local_1a50 = *(longlong*)local_1620;
    lVar12 = 1;
    lVar16 = 8;
    tmpl = *(longlong *)local_4e0;
    do {
        Ecarrys_1801a6dff(local_3a80, (uint)lVar12, (longlong*)(local_4e0 + lVar16));
       tmpl = tmpl+ *(longlong*)(local_4e0 + lVar12 * 8);
        *(longlong*)(local_910 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x4e);
    local_42f0 = local_42f0 + 0x17d0;
    lVar12 = 1;
    lVar16 = 8;
    tmpl= *(longlong*)local_1620;
    do {
        Ecarrys_1801a6ea1(pbVar21 + 0x1500, (uint)lVar12, (longlong*)(local_1620 + lVar16));
        tmpl = tmpl + *(longlong*)(local_1620 + lVar12 * 8);
        local_1a50[lVar12] = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    uVar23 = 0;
    do {
        uVar14 = 0x4d;
        if (uVar23 < 0x4d) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = 0x7b3e5f7abb73acc2;
        uVar25 = (uint)uVar14;
        uVar5 = (uint)uVar17;
        if (uVar5 <= uVar25) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + *(longlong*)(local_1620 + (uVar13 & 0xffffffff) * 8) *
                    *(longlong*)(local_4e0 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_910 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_910 + (ulonglong)(uVar5 - 1) * 8);
            }
            uVar14 = local_1a50[uVar10 - uVar5];
            if (0x4d < uVar23) {
                uVar14 = uVar14 - local_1a50[~uVar25 + uVar10];
            }
            lVar12 = (ulonglong)((uVar25 - uVar5) + 1) * 0x5988d88b45689bb6 + 0x7b3e5f7abb73acc2 +
                lVar12 * -0x6f2dd5616ce5113f + lVar16 * 0x157cfe4cc081d876 +
                uVar14 * 0x2982adf0d01081a1;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * 0x5b6ba0974e05bfa3 + 0x67d0b26878182f62;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4); 
    memcpy(local_1a50, (byte*)local_42e0, 0x168);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar23 = (ulonglong)
            ((*(int*)((longlong)local_1a50 + lVar12 * 4) *
                *(int*)((longlong)DAT_18094cf30 + uVar23) +
                *(int*)((longlong)DAT_18094cf50 + uVar23)) * 0x394075ef + 0xf8666254);
        uVar14 = uVar23 * -0x131de51b9e6efef3 + 0xa99e67b25c06dab4;
        iVar9 = 8;
        do {
            uVar14 = (uVar14 >> 4) + *(longlong*)(DAT_18094cf70 + (ulonglong)((uint)uVar14 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_1620 + lVar12 * 8) =
            uVar14 * -0x5ef9904d00000000 + uVar23 * -0x15553e294b265f17 + 0x4afd9c7ac2b49d7a;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0;
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 = tempout* ((longlong)local_42e8 * 0x6424db84626df18b + 0x595f61394a756827) +
            (longlong)local_42e8 * -0x27f303cb1a7e09f8 + -0x1da07695e3f559dd;
        uVar23 = lVar16 * 0x470d95e70e1e680b + 0x51781396abe4f830;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094cff0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x7a43e29d90000000 + lVar16 * -0x3561dc0eae60bad + 0x1c1305e909063ca8;
        lVar16 = lVar7 * 0x181d626abd2dde73 + 0xfda2008a73ef75;
        uVar23 = lVar7 * 0x2e545e4fda9efde1 + 0x449864fe749b5b97;
        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_1620 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_1620 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);
            memcpy(xmm2.data, &local_1620[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar20[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar20[lVar7 * 8], xmm2.data, 16);
            
            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x8d2821cb29e0c7f + 0x541cffb20fecc3f8;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d070 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x684ceab1d37c899b + 0x566ff24c2110d870;
        uVar23 = lVar16 * 0x1a530a60de55321d + 0xac7ae4cf6e1cd0d0;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d0f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
       tempout=
            (uVar23 * -0xfbad3f000000000 + lVar16 * -0x7d699be883bc11dd) * 0x28a362e8033ea351 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + -0x17696ae46643026;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a);
    lVar12 = 0x533719e4515877be;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * 0x7f7e15597f2da5a9 +
            lVar12 * -0x34c2565df759a529 + 0x63cbadeab6b7139e;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * -0x3e4bd22fa7e11543 + 0x512010fa0a8accc3;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d170 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x5c1c18d000000000 + *(longlong*)(&local_3150[56]) * -0x73cc76d085c1c18d +
            -0x2d411a36aeb73843;
        *(int*)(&local_22b0[lVar16*4-0x168]) =
            ((int)*(longlong*)(&local_3150[56]) * -0x10000000 + (int)lVar7 * -0x29370123 + -0x785ba807) *
            *(int*)((longlong)DAT_18094d1f0 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094d210 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4); 
    pbVar20 = local_30c0;
    Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x2d0);
    Ecarrys_1801a6f43(local_22b0, 0, (longlong*)local_1620);
    Ecarrys_1801a6fe5(local_42f0, 0, (longlong*)local_1a50);
    *(longlong *)local_4e0 =*(longlong*)local_1620;
    *(longlong*)local_910 =  local_1a50[0];
    lVar16 = 1;
    lVar12 = 8;
    tmpl= *(longlong*)local_1620;
    do {
        Ecarrys_1801a6f43(local_22b0, (uint)lVar16, (longlong*)(local_1620 + lVar12));
        pbVar21 = local_42f0;
        tmpl= tmpl + *(longlong*)(local_1620 + lVar16 * 8);
        *(ulonglong*)(local_4e0 + lVar16 * 8) = tmpl;
        lVar16 = lVar16 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar16 != 0x5a); 
    lVar12 = 1;
    lVar16 = 8;
    tmpl = local_1a50[0];
    do {
        Ecarrys_1801a6fe5(pbVar21, (uint)lVar12, (longlong*)((longlong)local_1a50 + lVar16));
        tmpl = tmpl + local_1a50[lVar12];
        *(ulonglong*)(local_910 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar16 = lVar16 + 8;
    } while (lVar12 != 0x5a);
    uVar23 = 0;
    do {
        uVar14 = 0x59;
        if (uVar23 < 0x59) {
            uVar14 = uVar23;
        }
        uVar10 = (uint)uVar23;
        uVar17 = (ulonglong)(uVar10 - 0x59);
        if (uVar10 < 0x59) {
            uVar17 = 0;
        }
        lVar12 = 0x7999b97e4a42ae9c;
        uVar25 = (uint)uVar17;
        uVar5 = (uint)uVar14;
        if (uVar25 <= uVar5) {
            uVar13 = uVar23 - uVar17;
            lVar12 = 0;
            do {
                lVar12 = lVar12 + local_1a50[uVar13 & 0xffffffff] * *(longlong*)(local_1620 + uVar17 * 8);
                uVar17 = uVar17 + 1;
                uVar13 = uVar13 - 1;
            } while (uVar14 + 1 != uVar17);
            lVar16 = *(longlong*)(local_4e0 + uVar14 * 8);
            if (0x59 < uVar23) {
                lVar16 = lVar16 - *(longlong*)(local_4e0 + (ulonglong)(uVar25 - 1) * 8);
            }
            lVar7 = *(longlong*)(local_910 + (ulonglong)(uVar10 - uVar25) * 8);
            if (0x59 < uVar23) {
                lVar7 = lVar7 - *(longlong*)(local_910 + (ulonglong)(~uVar5 + uVar10) * 8);
            }
            lVar12 = (ulonglong)((uVar5 - uVar25) + 1) * -0x19c8866e8b0dede6 + 0x7999b97e4a42ae9c +
                lVar12 * 0x352ba8a2de5680e7 + lVar16 * -0x527817a9debe876f +
                lVar7 * -0x43847659a5416ea;
        }
        *(longlong*)(local_30c0 + uVar23 * 8) = lVar12 * -0xcd66d63570297b1 + 0x1e5a4972b55170fc;
        uVar23 = uVar23 + 1;
    } while (uVar23 != 0xb4);
    memcpy(local_1a50, (byte*)local_42e0, 0x168);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x2d0);
    lVar12 = 0;
    do {
        uVar23 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar14 = (ulonglong)
            ((*(int*)((longlong)local_1a50 + lVar12 * 4) *
                *(int*)((longlong)DAT_18094d3b0 + uVar23) +
                *(int*)((longlong)DAT_18094d3d0 + uVar23)) * -0x233c36a1 + 0x49411c8a);
        uVar23 = uVar14 * 0x287386aa5949f907 + 0x3e4cad6681d19b07;
        iVar9 = 8;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d3f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        *(ulonglong*)(local_1620 + lVar12 * 8) =
            uVar23 * -0x4ccb30b500000000 + uVar14 * 0x525585cd8c8b61f3 + 0x25db83fecb151969;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar12 = 0; //CHECKED...
    tempout = *(longlong*)local_30c0;
    do {
        lVar16 = tempout * ((longlong)local_42e8 * -0x1e26953cbae8201 + -0x67958685c7d86955) +
            (longlong)local_42e8 * 0x7cc7b9d621b6f320 + -0x466e4207cddd9fce;
        uVar23 = lVar16 * 0x3be26c76c4339949 + 0x14c0c3855403fc10;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d470 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar7 = uVar23 * -0x142599fb50000000 + lVar16 * -0x7f938bbd1eef4863 + 0xa4aabf22c063306;
        lVar16 = lVar7 * -0x64d4c97e11f5103f + 0x579f62b2a466cb70;
        uVar23 = lVar7 * -0x1b2a4d24248b3af5 + 0x5e90aa3d3b3d61d0;
        xmm0.assign8(uVar23);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar16);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar7 = 0;
        do {
            uVar14 = *(ulonglong*)(local_1620 + lVar7 * 8);
            uVar17 = *(ulonglong*)(local_1620 + lVar7 * 8 + 8);
            lVar18 = *(longlong*)((longlong)(pbVar20 + lVar7 * 8) + 8);

            memcpy(xmm2.data, &local_1620[lVar7 * 8], 16);
            memcpy(xmm3.data, &pbVar20[lVar7 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar20[lVar7 * 8], xmm2.data, 16);
            lVar7 = lVar7 + 2;
        } while (lVar7 != 0x5a);
        uVar23 = *(longlong*)(local_30c0 + lVar12 * 8) * 0x4c4dbb3cb3380f81 + 0x9c6517f6637cb422;
        iVar9 = 7;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d4f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        lVar16 = uVar23 * -0x15c12298ca350185 + 0x27a36e6e8df823c4;
        uVar23 = lVar16 * 0x1089ff41ffd9c4d1 + 0xad6706ed1608e5ba;
        iVar9 = 9;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d570 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        tempout =
            (uVar23 * 0x4837fe3000000000 + lVar16 * -0x45feca911b03453) * -0x395d346c12fcc6a1 +
            *(longlong*)(local_30c0 + lVar12 * 8 + 8) + 0x64469f53195054b5;
        *(longlong*)(local_30c0 + lVar12 * 8 + 8) = tempout;
        lVar12 = lVar12 + 1;
        pbVar20 = pbVar20 + 8;
    } while (lVar12 != 0x5a); 
    lVar12 = -0x5594d1555cbf3e22;
    lVar16 = 0x5a;
    do {
        lVar7 = *(longlong*)(local_30c0 + lVar16 * 8) * -0x1ff3895d1d88c7a7 +
            lVar12 * 0x50d98406f383f859 + -0x5aa8b826e4ce6e55;
        Maybe_MEMSET_180512a50((char*)local_3150, 0xaa, 0x88);
        uVar23 = lVar7 * 0x3763d761e59ee237 + 0x149849d993cd443d;
        *(ulonglong*)local_3150 = uVar23;
        lVar12 = 0;
        do {
            uVar23 = (uVar23 >> 4) + *(longlong*)(DAT_18094d5f0 + (ulonglong)((uint)uVar23 & 0xf) * 8);
            *(ulonglong*)(local_3150 + lVar12 * 8 + 8) = uVar23;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        uVar23 = (ulonglong)((int)lVar16 - 0x5aU & 7);
        lVar12 = *(longlong*)(&local_3150[128]) * 0x337b121000000000 + *(longlong*)(&local_3150[56]) * 0x7508b220dcc84edf +
            -0x63d0462a8ea993e6;
        *(int*)(local_d40 + lVar16 * 4 - 0x168) =
            ((int)*(longlong*)(&local_3150[56]) * -0x70000000 + (int)lVar7 * -0x47ba136f + -0x29a64066) *
            *(int*)((longlong)DAT_18094d670 + uVar23 * 4) +
            *(int*)((longlong)DAT_18094d690 + uVar23 * 4);
        lVar16 = lVar16 + 1;
    } while (lVar16 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x4c0);
   longlong pbcnt=0x0;
   longlong rcnt = 0x0;
    {
        unsigned char dt [16]= {4,0,7,1,7,7,1,1,3,3,2,6,5,1,7,2};

        memcpy(xmm7.data, dt, 16);
    }
    do {
        uVar10 = *(uint*)(local_d40 + (longlong)pbcnt * 4);
        lVar12 = 0;
        do {
            *(char*)((longlong)&local_42a4 + lVar12) = (char)uVar10;
            uVar25 = local_42a4;
            uVar10 = uVar10 >> 8;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 4);
        local_42a4 = local_42a4 & 0xfffffff;
        *(uint*)local_1620 = local_42a4;
        *(short*)local_2b20 = 0x707;
        bVar19 = 0;
        *(ulonglong*)local_2b20 = 0;
        uVar23 = 0;
        do {
            local_2b20[uVar23 + 2] = local_1620[(uVar23 & 0xffffffff) >> 2] >> (bVar19 & 6) & 3;
            uVar23 = uVar23 + 1;
            bVar19 = bVar19 + 2;
        } while (uVar23 != 0xe);
        ConstUser_18016b077(0x10000037a62, local_2b20, local_2b20, local_3150);
        local_42e8 = ((ulonglong)((uint)pbcnt & 7) * 0x10);
        pdat = DAT_18094d6b0 + (longlong)local_42e8;
        memcpy(local_1a50,xmm7.data,16);
        rcnt = pbcnt;
        ConstUser_18016b077(0x1000000cf16, local_3150, local_3150, local_2b20);
        ConstUser_18016b077(0x1000003948c, pdat, pdat, local_1620);
        ConstUser_18016b077(0x10000010727, local_2b20, local_2b20, local_4e0);
        iVar9 = 0x1c;
        do {
            ConstUser_18016b077(0x10000022768, local_1620, (byte*)local_1a50, local_910);
            PFUN_180119595((uint*)DAT_18094d7c0, (uint*)DAT_1814443fc, 4, 0x5bc9c1ca);
            ConstUser_18016b077(0x100000323ab, DAT_1814443fc, local_910, local_1170);
            ConstUser_18016b077(0x100000344a8, local_2b20, local_1170, local_2710);
            ConstUser_18016b077(0x10000039472, local_4e0, local_2710, local_4e0);
            ConstUser_18016b077(0x10000022663, local_2b20, local_2b20, local_2b20);
            ConstUser_18016b077(0x100000332b9, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
            iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        ConstUser_18016b077(0x1000001050f, local_4e0, local_2b20, local_22e0);
        pbcnt = rcnt;
        ConstUser_18016b077(0x10000005d20, local_22e0, DAT_18094d730 + (longlong)local_42e8,
            local_30c0 + (longlong)rcnt * 0x10);
        pbcnt = pbcnt + 1;
    } while (pbcnt != 0x4c);
    ConstUser_18016b077(0x1000000ae06, local_30c0, local_30c0, local_2b20);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x4b0);
    lVar12 = 0;
    do {
        ConstUser_18016b077(0x100000362ba, local_30c0 + lVar12 + 0x10, local_30c0 + lVar12 + 0x10,
            local_1620 + lVar12);
        lVar12 = lVar12 + 0x10;
    } while (lVar12 != 0x4b0); 
    Maybe_MEMSET_180512a50((char*)(local_1a50 + 2), 0xaa, 0x41a);
    puVar22 = local_1a50 + 2;
    memcpy(local_1a50, local_2b20, 16);

    lVar12 = 2;
    do {
        uVar23 = *(ulonglong*)(local_1620 + lVar12);
        *(undefined8*)((longlong)puVar22 + 6) = *(undefined8*)(local_1620 + lVar12 + 6);
        *puVar22 = uVar23;
        puVar22 = (ulonglong*)((longlong)puVar22 + 0xe);
        lVar12 = lVar12 + 0x10;
    } while (lVar12 != 0x4b2);
    ConstUser_18016b077(0x425000000059, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1e80);
    Maybe_MEMSET_180512a50((char*)local_22b0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x426);
    memcpy(local_1a50, DAT_18094d7d0, 0x426);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x426);
    OtherConstUser_180169484(0x4425000030201, (byte*)local_1e80, (byte*)local_1e80, local_30c0);
    OtherConstUser_180169484(0x105c00f00002ce63, (byte*)&local_42a0, (byte*)&local_42a0, local_1620);
    ConstUser_18016b077(0x42600000555b, local_30c0, local_30c0, local_4e0);
    iVar9 = 0x1a;
    do {
        Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x426);
        Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x426);
        Maybe_MEMSET_180512a50(local_1170, 0xaa, 0x426);
        ConstUser_18016b077(0x4260000354ac, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094dc00, (uint*)DAT_181444410, 0x10a, 0xe098f31e);
        ConstUser_18016b077(0x426000027608, DAT_181444410, local_910, local_d40);
        ConstUser_18016b077(0x426000038fc3, local_30c0, local_d40, local_1170);
        ConstUser_18016b077(0x42600002bb24, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x426000034f75, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x426000036872, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    ConstUser_18016b077(0x426000004b63, local_4e0, local_30c0, local_22b0);
    Maybe_MEMSET_180512a50((char*)local_2b20, 0xaa, 0x403);
    ConstUser_18016b077(0x25000030764, local_22b0, local_22b0, local_3150);
    {
        unsigned char dt[16] = { 0x01,1,1,7,1,3,1,7,2,5,3,1,7,2,0,5 };
        memcpy(xmm0.data, dt, 16);
    }
    memcpy(&local_1a50[2], xmm0.data, 16);
    {
        unsigned char dt[16] = { 4,3,3,4, 4,6,5,2, 5,3,3,2, 4,5,1,3 };
        memcpy(xmm0.data, dt, 16);
    }
    memcpy(local_1a50, xmm0.data, 16);
    *(longlong*)(&(((byte*)local_1a50)[29])) = 0x404000207050002;
    ConstUser_18016b077(0x250000023fa, local_42d8, local_42d8, local_30c0);
    ConstUser_18016b077(0x25000037501, local_3150, local_3150, local_1620);
    ConstUser_18016b077(0x25000004193, local_30c0, local_30c0, local_4e0);
    iVar9 = 0x46;
    do {

        ConstUser_18016b077(0x2500002696b, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094e060, (uint*)DAT_18144483c, 10, 0x31cc1fb6);
        ConstUser_18016b077(0x250000191bf, DAT_18144483c, local_910, local_d40);
        ConstUser_18016b077(0x2500000f9ef, local_30c0, local_d40, local_1170);
        ConstUser_18016b077(0x2500001336c, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x25000020777, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x250000054f4, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    ConstUser_18016b077(0x2500001084d, local_4e0, local_30c0, local_22e0);//local_4e0 mismatch
    Maybe_MEMSET_180512a50((char*)local_2710, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x426);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x426);
    memcpy(local_1a50, DAT_18094e090, 0x426);
    Maybe_MEMSET_180512a50((char*)local_4e0, 0xaa, 0x426);
    OtherConstUser_180169484(0x8c403000011e40, local_3840, local_3840, local_30c0);
    OtherConstUser_180169484(0x100402500000b9ed, local_22e0, local_22e0, local_1620);
    ConstUser_18016b077(0x426000021981, local_30c0, local_30c0, local_4e0);
    int iVar26 = 0x46;
    do {
        Maybe_MEMSET_180512a50((char*)local_910, 0xaa, 0x426);
        Maybe_MEMSET_180512a50((char*)local_d40, 0xaa, 0x426);
        Maybe_MEMSET_180512a50(local_1170, 0xaa, 0x426);
        ConstUser_18016b077(0x42600001c426, local_1620, (byte*)local_1a50, local_910);
        PFUN_180119595((uint*)DAT_18094e4c0, (uint*)DAT_181444868, 0x10a, 0x1b55e9cb);
        ConstUser_18016b077(0x42600003242a, DAT_181444868, local_910, local_d40);
        ConstUser_18016b077(0x426000028b44, local_30c0, local_d40, local_1170);
        ConstUser_18016b077(0x4260000227f2, local_4e0, local_1170, local_4e0);
        ConstUser_18016b077(0x4260000183b5, local_30c0, local_30c0, local_30c0);
        ConstUser_18016b077(0x42600001f34b, (byte*)local_1a50, (byte*)local_1a50, (byte*)local_1a50);
        iVar26 = iVar26 + -1;
    } while (iVar26 != 0);
    ConstUser_18016b077(0x4260000319f7, local_4e0, local_30c0, local_2710); //seems OK so far... 
    ConstUser_18016b077(0x426000008b35, local_2710, local_22b0, local_2710);
    OtherConstUser_180169484(0x403008c0d78d, local_2710, local_2710, local_2b20);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x404);
    Maybe_MEMSET_180512a50((char*)local_1620, 0xaa, 0x404);
    Maybe_MEMSET_180512a50((char*)local_1a50, 0xaa, 0x404);
    MB_Zeropad_180113d26(0x2018, local_2b20, 0x2020, local_30c0);
    MB_Zeropad_180113d26(0x2018, local_3840, 0x2020, local_1620);
    local_30c0[1027] = 4;
    local_1620[1027] = 6;
    ConstUser_18016b077(0x40400002f22a, local_30c0, local_1620, (byte*)local_1a50);
    if (__metaskip1)
    {
        if (((byte*)local_1a50)[0x403] == '\x01')
        {
            ((byte*)local_1a50)[0x403] = '\x00';
        }
    }

    if (((byte*)local_1a50)[0x403] == '\x01') {
        uVar23 = 0x40200000d35a;
        pbVar20 = local_2b20;
    }
    else {
        pbVar20 = local_30c0;
        Maybe_MEMSET_180512a50((char*)pbVar20, 0xaa, 0x403);
        ConstUser_18016b077(0x40300002f77d, local_2b20, local_3840, pbVar20);
        uVar23 = 0x402000033f8a;
    }
    ConstUser_18016b077(uVar23, pbVar20, pbVar20, (byte*)local_4290);
    Maybe_MEMSET_180512a50((char*)local_30c0, 0xaa, 0x402);

    Crazed_18016cddb(local_3e88, (byte*)local_4290, local_30c0);
    OtherConstUser_180169484(0x3b040200001096c, local_30c0, local_30c0, local_42c8);
    return;
}


void ECCarry_1801a5ef6(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091e130)[lVar2] +
            (INT_18091e150)[lVar2]) * 0x30f5ae3f + 0xfaee2c59);
    uVar3 = uVar5 * 0x2877ae1b1440b05 + 0xf73384b898f7f37d;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091e170)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x7e98c48300000000 + uVar5 * 0xf06a533cf39778f + 0x2aa5d0c1bfd3c4ef;
    return;
}
void ECCarry_1801a5db2(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091dcb0)[lVar2] +
            (INT_18091dcd0)[lVar2]) * 0x4a123d2f + 0xa924f30b);
    uVar3 = uVar5 * 0x5bcfd4644a92838d + 0xa76ba39317434285;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091dcf0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x62f3ce500000000 + uVar5 * -0x4fbd2e1380c7b921 + -0xc6d9bc808f60982;
    return;
}
void ECCarry_1801a5e54(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091dd70)[lVar2] +
            (INT_18091dd90)[lVar2]) * 0x6fac89ff + 0xb8f22963);
    uVar3 = uVar5 * 0x6ef6c5f167b814fd + 0xba12a033e270577;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091ddb0)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * -0x2560ae9300000000 + uVar5 * 0x34555b861cd80347 + -0x4bd9b74240ee5295;
    return;
}


void ECCarry_1801a5f98(byte* param_1, uint param_2, longlong* param_3)

{
    uint uVar1;
    longlong lVar2;
    ulonglong uVar3;
    int iVar4;
    ulonglong uVar5;

    uVar1 = param_2 + 7;
    if (-1 < (int)param_2) {
        uVar1 = param_2;
    }
    lVar2 = (longlong)(int)(param_2 - (uVar1 & 0xfffffff8));
    uVar5 = (ulonglong)
        ((*(int*)(param_1 + (longlong)(int)param_2 * 4) * (INT_18091e1f0)[lVar2] +
            (INT_18091e210)[lVar2]) * -0x25d1353b + 0xad573c70);
    uVar3 = uVar5 * 0x2ce0d4b400adfa71 + 0x1a468f30e0926911;
    iVar4 = 8;
    do {
        uVar3 = (uVar3 >> 4) + (QWORD_18091e230)[(uint)uVar3 & 0xf];
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *param_3 = uVar3 * 0x3177185d00000000 + uVar5 * -0x7358243d9a35930d + 0x2bc98e0729ec2bd3;
    return;
}




void ManyMutiplies_1801720e0
(byte* param_1, byte* param_2, byte* param_3, byte* param_4, byte* param_5, byte* out)

{
    ushort uVar1;
    longlong lVar2;
    byte* pbVar3;
    byte bVar4;
    longlong lVar6;
    ulonglong uVar7;
    ulonglong uVar8;
    char cVar11;
    longlong lVar12;
    ulonglong uVar15;
    ulonglong uVar16;
    longlong* plVar17;
    ulonglong uVar19;
    longlong lVar20;
    int iVar21;
    int iVar22;
    byte* pbVar23;
    byte* pbVar24;
    uint uVar25;
    ushort uVar26;
    uint uVar27;
    bool bVar28;
    undefined8 uVar33;
    undefined4 uVar36;
    undefined4 uVar37;
    undefined4 uVar38;
    undefined4 uVar42;
    undefined4 uVar43;
    undefined4 uVar44;
    uint uVar45;
    int iVar46;
   byte* local_res20= param_5;
    byte* p1_holder;
    longlong var_st2;
    byte* pbStack364184;
    byte* p4_holder;
    longlong var_stack;
    ulonglong uStack364168;
    ulonglong uStack364160;
    ulonglong uStack364152;
    byte* pbStack364144;
    byte auStack364128[321848];//[RSP + 0x70]
    longlong* alStack361960 = (longlong*)(auStack364128+ 0x878);//[9990];
    longlong* alStack282040= (longlong*)(auStack364128 + 0x140a8);//[9990];//+0x140a8??
    longlong* alStack202120 = (longlong*)(auStack364128 + 0x278d8);//0x278d8
    longlong* alStack122200 = (longlong*)(auStack364128 + 0x3b108);//0x3b108
    int aiStack42632[90];
    int local_a520[92];
    byte local_a3b0[360];
    int local_a240[92];
    int local_a0d0[92];
    int  local_9f60[90];
    byte local_9df0[360];
    byte local_9c80[360];
    int local_9b10[92];
    int local_99a0[92];
    int local_9830[92];
    int local_96c0[92];
    uint local_9550[92];
    uint local_93e0[92];
    int local_9270[92];
    int local_9100[92];
    byte local_8f90[1262];
    byte local_8aa0[720];
    short local_87d0[360];
    byte local_8500[360];
    byte local_8390[360];
    byte local_8220[360];
    longlong local_80b0[4096];
    reg16 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5,  xmm7, xmm8, xmm9, xmm10;
    p4_holder = param_4;
    pbStack364144 = param_3;
    Maybe_MEMSET_180512a50((char*)local_9100, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_9270, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_93e0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_9550, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_96c0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_9830, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_99a0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_9b10, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x4ee);
    ConstUser_18016b077(0x4ee00002ec5d, param_2, param_2, local_8f90);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x5a0);
    lVar6 = 0;
    iVar22 = 0;
    do {
        lVar12 = (longlong)iVar22;
        uVar36 = *(undefined4*)(local_8f90 + lVar12 + 4);
        uVar37 = *(undefined4*)(local_8f90 + lVar12 + 8);
        uVar38 = *(undefined4*)(local_8f90 + lVar12 + 0xc);
        *(undefined4*)(auStack364128 + lVar6) = *(undefined4*)(local_8f90 + lVar12);
        *(undefined4*)(auStack364128 + lVar6 + 4) = uVar36;
        *(undefined4*)(auStack364128 + lVar6 + 8) = uVar37;
        *(undefined4*)(auStack364128 + lVar6 + 0xc) = uVar38;
        iVar22 = iVar22 + 0xe;
        lVar6 = lVar6 + 0x10;
    } while (lVar6 != 0x5a0);
    lVar6 = 0;

    p1_holder = param_1;

    do {
        ConstUser_18016b077(0x1000001c0cb, auStack364128 + lVar6, auStack364128 + lVar6,
            (byte*)((longlong)local_80b0 + lVar6));
        lVar6 = lVar6 + 0x10;
    } while (lVar6 != 0x5a0);
    uStack364152 = 0x8010000022ea1;
    lVar6 = 0;
    uVar36 = 0xaaaaaaaa;
    uVar37 = 0xaaaaaaaa;
    uVar38 = 0xaaaaaaaa;
    iVar22 = -0x55555556;
   
    uVar42 = 0x4040606;
    uVar43 = 0x2070105;
    uVar44 = 0x60400;
    {
        unsigned char dt[16] = {3,6,4,4,  6,6,4,4, 5,1,7,2,  0,4,6,0   };
        memcpy(xmm9.data, dt, 16);
    }

    uStack364160 = 0x12000037c7c;
    uStack364168 = 0x1200002d3a1;
   // pbStack364200 = (byte*)
    ulonglong cnst1= 0x1200000837d;
    xmm7.assign8(0);
    {
        unsigned char dt[16] = {1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1 };
        memcpy(xmm8.data, dt, 16);
    }
    xmm10.PSHUFD(xmm8,0xf5);
    ulonglong counter;
    do {
        uVar15 = (ulonglong)((uint)lVar6 & 7);
        longlong minor = (uVar15 * 9);
        memcpy( local_87d0,xmm9.data,16);
        local_87d0[8] = 0x105;
        counter = lVar6;
        ConstUser_18016b077(uStack364160, DAT_18091a710 + uVar15 * 0x12, DAT_18091a710 + uVar15 * 0x12,
            auStack364128);
        OtherConstUser_180169484
        (0x8010000022ea1, (byte*)(local_80b0 + lVar6 * 2), (byte*)(local_80b0 + lVar6 * 2),
            local_8f90);
        ConstUser_18016b077(uStack364168, auStack364128, auStack364128, local_8aa0);
        iVar21 = 0x1c;
        do {
     
            ConstUser_18016b077((ulonglong)cnst1, local_8f90, (byte*)local_87d0, local_8220);
            PFUN_180119595((uint*)DAT_18091a850, (uint*)DAT_18136f704, 5, 0xeac23ffb);
            ConstUser_18016b077(0x1200001f97d, DAT_18136f704, local_8220, local_8390);
            ConstUser_18016b077(0x1200003646d, auStack364128, local_8390, local_8500);
            ConstUser_18016b077(0x12000023d93, local_8aa0, local_8500, local_8aa0);
            ConstUser_18016b077(0x12000002337, auStack364128, auStack364128, auStack364128);
            ConstUser_18016b077(0x120000046d5, (byte*)local_87d0, (byte*)local_87d0, (byte*)local_87d0);
            iVar21 = iVar21 + -1;
        } while (iVar21 != 0);
        ConstUser_18016b077(0x120000155d7, local_8aa0, auStack364128, local_9c80);
        ConstUser_18016b077(0x120000218ce, local_9c80, DAT_18091a7a0 + (longlong)minor * 2,
            local_9df0);
        ConstUser_18016b077(0x1200001efdd, local_9df0, local_9df0, auStack364128);
        auStack364128[17] = auStack364128[17] & 3;
        local_9f60[0] = 0;
        bVar4 = 0;
        uVar15 = 0;
        do {
            pbVar24 = (byte*)((longlong)local_9f60 + ((uVar15 & 0xffffffff) >> 2));
            *pbVar24 = *pbVar24 | (auStack364128[uVar15 + 2] & 3) << (bVar4 & 6);
            uVar15 = uVar15 + 1;
            bVar4 = bVar4 + 2;
        } while (uVar15 != 0x10);
        xmm0.assign4(local_9f60[0]);
        xmm0.PUNPCKLBW(xmm7);
        xmm0.PUNPCKLWD(xmm7);
        xmm1.PSHUFD(xmm0, 0xf5);
        xmm0.PMULUDQ(xmm8);
        xmm0.PSHUFD(xmm0, 0xe8);
        xmm1.PMULUDQ(xmm10);
        xmm1.PSHUFD(xmm1, 0xe8);
        xmm0.PUNPCKLDQ(xmm1);
        xmm1.PSHUFD(xmm0, 0xee);
        xmm1.POR(xmm0);
        xmm0.PSHUFD(xmm1, 0x55);
        xmm0.POR(xmm1);
        local_93e0[counter] = *(uint*)xmm0.data;
        lVar6 = counter + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x4ee);
    ConstUser_18016b077(0x4ee00000a05b, param_3, param_3, local_8f90);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x5a0);
    lVar6 = 0;
    iVar21 = 0;
    do {
        lVar12 = (longlong)iVar21;
        undefined4 uVar41 = *(undefined4*)(local_8f90 + lVar12 + 4);
        uVar42 = *(undefined4*)(local_8f90 + lVar12 + 8);
        uVar43 = *(undefined4*)(local_8f90 + lVar12 + 0xc);
        *(undefined4*)(auStack364128 + lVar6) = *(undefined4*)(local_8f90 + lVar12);
        *(undefined4*)(auStack364128 + lVar6 + 4) = uVar41;
        *(undefined4*)(auStack364128 + lVar6 + 8) = uVar42;
        *(undefined4*)(auStack364128 + lVar6 + 0xc) = uVar43;
        iVar21 = iVar21 + 0xe;
        lVar6 = lVar6 + 0x10;
    } while (lVar6 != 0x5a0);
    lVar6 = 0;
    do {
        ConstUser_18016b077(0x1000003942b, auStack364128 + lVar6, auStack364128 + lVar6,
            (byte*)((longlong)local_80b0 + lVar6));
        lVar6 = lVar6 + 0x10;
    } while (lVar6 != 0x5a0);
    lVar6 = 0;
    uVar42 = 0x3030301;
    uVar43 = 0x3050201;
    uVar44 = 0x6060203;
    {
        unsigned char dt[16] = {1,7,1,1, 1,3,3,3, 1,2,5,3, 3,2,6,6 };
        memcpy(xmm9.data, dt, 16);
    }

    uStack364160 = 0x1200000d012;
    uStack364152 = uStack364152 + 0x7cb1;
    uStack364168 = 0x12000017118;
    var_st2 = 0x12000009aed;
    xmm7.assign8(0);
    counter = 0;
    do {
        uVar15 = (ulonglong)((uint)lVar6 & 7);
        longlong minor = (uVar15 * 9);
        memcpy(local_87d0, xmm9.data, 16);
        local_87d0[8] = 0x404;
        counter = lVar6;
        ConstUser_18016b077(uStack364160, DAT_18091a870 + uVar15 * 0x12, DAT_18091a870 + uVar15 * 0x12,
            auStack364128);
        OtherConstUser_180169484
        (uStack364152, (byte*)(local_80b0 + lVar6 * 2), (byte*)(local_80b0 + lVar6 * 2),
            local_8f90);
        ConstUser_18016b077(uStack364168, auStack364128, auStack364128, local_8aa0);
        iVar21 = 0x1c;
        do {
            ConstUser_18016b077((ulonglong)var_st2, local_8f90, (byte*)local_87d0, local_8220);
            PFUN_180119595((uint*)DAT_18091a9b0, (uint*)DAT_18136f71c, 5, 0xcff29fc9);
            ConstUser_18016b077(0x1200000b356, DAT_18136f71c, local_8220, local_8390);
            ConstUser_18016b077(0x12000037ba3, auStack364128, local_8390, local_8500);
            ConstUser_18016b077(0x12000027481, local_8aa0, local_8500, local_8aa0);
            ConstUser_18016b077(0x12000006f88, auStack364128, auStack364128, auStack364128);
            ConstUser_18016b077(0x1200000d2ee, (byte*)local_87d0, (byte*)local_87d0, (byte*)local_87d0);
            iVar21 = iVar21 + -1;
        } while (iVar21 != 0);
        ConstUser_18016b077(0x12000035dfe, local_8aa0, auStack364128, local_9c80);
        ConstUser_18016b077(0x120000031f8, local_9c80, DAT_18091a900 + (longlong)minor * 2,
            local_9df0);
        ConstUser_18016b077(0x12000033f25, local_9df0, local_9df0, auStack364128);
        auStack364128[17] = auStack364128[17] & 3;
        local_9f60[0] = 0;
        bVar4 = 0;
        uVar15 = 0;
        do {
            pbVar24 = (byte*)((longlong)local_9f60 + ((uVar15 & 0xffffffff) >> 2));
            *pbVar24 = *pbVar24 | (auStack364128[uVar15 + 2] & 3) << (bVar4 & 6);
            uVar15 = uVar15 + 1;
            bVar4 = bVar4 + 2;
        } while (uVar15 != 0x10);
        xmm0.assign4(*(uint*)local_9f60);
        xmm0.PUNPCKLBW(xmm7);
        xmm0.PUNPCKLWD(xmm7);
        xmm1.PSHUFD(xmm0, 0xf5);
        xmm0.PMULUDQ(xmm8);
        xmm0.PSHUFD(xmm0, 0xe8);
        xmm1.PMULUDQ(xmm10);
        xmm1.PSHUFD(xmm1, 0xe8);
        xmm0.PUNPCKLDQ(xmm1);
        xmm1.PSHUFD(xmm0, 0xee);
        xmm1.POR(xmm0);
        xmm0.PSHUFD(xmm1, 0x55);
        xmm0.POR(xmm1);
        local_9550[counter] = *(uint*)xmm0.data;
        lVar6 = (longlong)counter + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
      
            *(uint*)(local_8aa0 + lVar6 * 4) =
                local_93e0[lVar6] * *(int*)((longlong)DAT_18091a9d0 + uVar15) +
                *(int*)((longlong)DAT_18091a9f0 + uVar15);
      
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x128);
    lVar6 = 0;
    do {
        lVar12 = lVar6 + 1;
        uVar15 = (ulonglong)((uint)lVar12 & 7);
        uVar19 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(auStack364128 + lVar6 * 4) =
            (*(int*)(local_8aa0 + lVar6 * 4 + 4) * *(int*)(DAT_18091aa10 + uVar15 * 4) +
                *(int*)(DAT_18091aa30 + uVar15 * 4)) * *(int*)((longlong)DAT_18091aa50 + uVar19) +
            *(int*)((longlong)DAT_18091aa70 + uVar19);
        lVar6 = lVar12;
    } while (lVar12 != 0x49);
    *(uint *) &auStack364128[292] = 0xf22d77dc;
    local_80b0[36] =
        local_80b0[36] & 0xffffffffU |
        (ulonglong)(*(int*)local_8aa0 * -0x5792bd51 + 0x3c7c056d) << 0x20;
    lVar6 = 0x48;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)((longlong)local_80b0 + lVar6 * 4) =
            *(int*)((longlong)DAT_18091aa90 + uVar15) * -0x7a9bbae +
            *(int*)((longlong)DAT_18091aab0 + uVar15);
        bVar28 = lVar6 != 0;
        lVar6 = lVar6 + -1;
    } while (bVar28);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x128);
    lVar6 = 0;
    do {
        *(uint*)(&local_8f90[lVar6 * 4]) = (INT_18091aad0)[(uint)lVar6 & 7];
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)((longlong)local_80b0 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091aaf0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(auStack364128 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091ab10 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    iVar46 = -0x1476600b;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * 0x3782609f + *(int*)(local_8f90 + lVar6 * 4);
        uVar45 = iVar21 * -0x444202f1 + 0xb216d82;
        *(uint *) local_a3b0 =  uVar45;
        lVar12 = 0;
        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091ab30 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[28]) * 0x27c0fcb1 + *(int*)(&local_a3b0[32]) * -0x7c0fcb10 + 0x6e0bc617;
        *(int*)(local_8390 + lVar6 * 4) =
            (iVar21 * -0x3e41a7f1 + *(int*)(&local_a3b0[28]) * -0x10000000 + -0x70ff6a6) *
            *(int*)((longlong)DAT_18091ab70 + uVar15) + *(int*)((longlong)DAT_18091ab90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    *(ulonglong *)local_9f60 = 0x742d7c5edc0d96b9;
    local_9f60[2] = 0x60c1d3f1;
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x250);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 600);
    lVar12 = 0;
    *(ulonglong*)auStack364128=0;
    *(ulonglong*)local_9c80 = 0;
    lVar6 = 0;
    while (true) {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)local_8aa0 * *(int*)((longlong)DAT_18091abb0 + uVar15) +
                *(int*)((longlong)DAT_18091abd0 + uVar15)) * 0x1678edbb + 0xea3c84b3);
        uVar19 = uVar15 * -0x4b2fc641c8c0321 + 0x7654e170d443c330;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091abf0 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar19 * -0x65d3f87700000000 + uVar15 * 0x7a30f8217eaf93a9 + 0x780ab4909b6ac45f;
        local_80b0[lVar6] = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 0x4a) break;
        *(int*)local_8aa0 = *(int*)(local_8aa0 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    iVar46 = -0x23f26947;
    lVar12 = 0;
    lVar6 = 0;
    while (true) {
        uVar19 = (ulonglong)
            ((iVar46 * *(int*)((longlong)DAT_18091ac70 + lVar6 * 4) +
                *(int*)((longlong)DAT_18091ac7c + lVar6 * 4)) * -0x6fcfabb1 + 0x9177cf35);
        uVar15 = uVar19 * -0x22d572b045c89501 + 0xaae4943c4fc4411f;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091ac90 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x44f1bad300000000 + uVar19 * -0x467bcb33ca8689d3 + -0x487d9499afc619a8;
        *(longlong*)(local_9df0 + lVar6 * 8) = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(local_9c80 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 3) break;
        iVar46 = *(int*)((longlong)local_9f60 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    lVar6 = 0x39661011cc967688;
    uVar15 = 1;
    uVar19 = 0;
    do {
        uVar45 = (uint)uVar19;
        uVar8 = (ulonglong)(uVar45 - 2);
        if (uVar45 < 2) {
            uVar8 = 0;
        }
        uVar16 = uVar19 - uVar8;
        if (uVar8 <= uVar19) {
            lVar12 = 0;
            uVar7 = uVar8;
            do {
                lVar12 = lVar12 + *(longlong*)(local_9df0 + (uVar16 & 0xffffffff) * 8) * local_80b0[uVar7];
                uVar7 = uVar7 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar15 != uVar7);
            uVar16 = (ulonglong)((uVar45 + 1) - (int)uVar8);
            lVar6 = uVar16 * -0x3c753f7af4745990 + lVar6 + lVar12 * -0x6aa37bdf0f742535 +
                (*(longlong*)(auStack364128 + uVar19 * 8 + 8) -
                    *(longlong*)(auStack364128 + uVar8 * 8)) * -0x5d0d53773461c788 +
                *(longlong*)(local_9c80 + uVar16 * 8) * 0x3af1d7c8c88f8f06;
        }
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar6 * -0x55e898e2f0f35a1 + 0xbc3cdbeab13ada1f;
        *(ulonglong*)local_8f90=  uVar8;
        lVar12 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091ad10 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar12 * 8 + 8) = uVar8;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        iVar46 = (int)lVar6;
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x63e119f000000000 + *(longlong*)(&local_8f90[56]) * 0x2ed89aa0063e119f +
            -0x1d6c86b6898b8841;
        uVar8 = (ulonglong)(uVar45 * 4 & 0x1c);
        *(int*)(local_8220 + uVar19 * 4) =
            ((int)*(longlong*)(&local_8f90[56]) * 0x50000000 + iVar46 * -0x4286b19b + 0x62fa0ec6) *
            *(int*)((longlong)DAT_18091ad90 + uVar8) + *(int*)((longlong)DAT_18091adb0 + uVar8);
        uVar19 = uVar19 + 1;
        uVar15 = uVar15 + 1;
    } while (uVar19 != 0x4a);
    *(ulonglong *)local_9f60 = 0xa9977f1b2438497d;
    local_9f60[2] = 0x606ac79e;
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x250);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 600);
    lVar6 = 0;
    *(ulonglong*)auStack364128=0;
    *(ulonglong*)local_9c80 = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((*(int*)(local_8390 + lVar12 * 4) * *(int*)((longlong)DAT_18091add0 + uVar15) +
                *(int*)((longlong)DAT_18091adf0 + uVar15)) * -0xe26a26b + 0x32dc04bd);
        uVar15 = uVar19 * 0x3935429f7b6f4a47 + 0xac8fcfe2d55093f1;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091ae10 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x56105d0d00000000 + uVar19 * -0x38423473112909b + 0x3ee33d71613c9bc7;
        local_80b0[lVar12] = lVar20;
        lVar6 = lVar6 + lVar20;
        *(longlong*)(auStack364128 + lVar12 * 8 + 8) = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x4a);
    iVar46 = 0x2438497d;
    lVar12 = 0;
    lVar6 = 0;
    while (true) {
        uVar19 = (ulonglong)
            ((iVar46 * *(int*)((longlong)DAT_18091ae90 + lVar6 * 4) +
                *(int*)((longlong)DAT_18091ae9c + lVar6 * 4)) * -0x415b6407 + 0x514491fd);
        uVar15 = uVar19 * 0xa896ea6ce8e5009 + 0xf879efa8ae002fd6;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091aeb0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x59869eab00000000 + uVar19 * -0x54550a2ad42b0403 + 0x3aae6b9eed9dd6dc;
        *(longlong*)(local_9df0 + lVar6 * 8) = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(local_9c80 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 3) break;
        iVar46 = *(int*)((longlong)local_9f60 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    lVar6 = -0x51ffd56e7ce49fd2;
    uVar15 = 1;
    uVar19 = 0;
    do {
        uVar45 = (uint)uVar19;
        uVar8 = (ulonglong)(uVar45 - 2);
        if (uVar45 < 2) {
            uVar8 = 0;
        }
        uVar16 = uVar19 - uVar8;
        if (uVar8 <= uVar19) {
            lVar12 = 0;
            uVar7 = uVar8;
            do {
                lVar12 = lVar12 + *(longlong*)(local_9df0 + (uVar16 & 0xffffffff) * 8) * local_80b0[uVar7];
                uVar7 = uVar7 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar15 != uVar7);
            uVar16 = (ulonglong)((uVar45 + 1) - (int)uVar8);
            lVar6 = uVar16 * 0x7ced494f9608606 + lVar6 + lVar12 * -0x7bf88d54ab5ef14d +
                (*(longlong*)(auStack364128 + uVar19 * 8 + 8) -
                    *(longlong*)(auStack364128 + uVar8 * 8)) * -0x2a1227da71cc3adf +
                *(longlong*)(local_9c80 + uVar16 * 8) * -0x4f3b8bfad7ff6e0e;
        }
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar6 * -0x1a1747955eb85d7d + 0x245b1555c2bb1650;
        *(ulonglong *)local_8f90=uVar8;
        lVar12 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091af30 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar12 * 8 + 8) = uVar8;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        iVar46 = (int)lVar6;
        lVar6 = *(longlong *)(&local_8f90[128]) * 0x434c3d5000000000 + *(longlong*)(&local_8f90[56]) * 0x7c7bcb1aebcb3c2b +
            0x7ffc6ede4fe88090;
        uVar8 = (ulonglong)(uVar45 * 4 & 0x1c);
        *(int*)(local_8500 + uVar19 * 4) =
            (iVar46 * 0x34a87a65 + (int)*(longlong*)(&local_8f90[56]) * -0x70000000 + 0x2398d6cf) *
            *(int*)((longlong)DAT_18091afb0 + uVar8) + *(int*)((longlong)DAT_18091afd0 + uVar8);
        uVar19 = uVar19 + 1;
        uVar15 = uVar15 + 1;
    } while (uVar19 != 0x4a);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x128);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8f90 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091aff0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(local_8220 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b010 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(local_8500 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b030 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    iVar46 = 0x25b481cc;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * 0x445b2077 + *(int*)(local_8f90 + lVar6 * 4);
        uVar45 = iVar21 * -0x5658f9fd + 0x2a80e0cb;
        *(uint *)local_a3b0 =  uVar45;
        lVar12 = 0;
     
        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091b050 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[32]) * 0x486f1930 + *(int*)(&local_a3b0[28]) * 0x1b790e6d + 0x50eb9113;
        *(int*)(local_87d0 + lVar6 * 2) =
            (iVar21 * 0x23fad359 + *(int*)(&local_a3b0[28]) * -0x30000000 + 0x6f9c38c2) *
            *(int*)((longlong)DAT_18091b090 + uVar15) + *(int*)((longlong)DAT_18091b0b0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        local_96c0[lVar6] =
            *(int*)(local_87d0 + lVar6 * 2) * *(int*)((longlong)DAT_18091b0d0 + uVar15) +
            *(int*)((longlong)DAT_18091b0f0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0x4a;
    do {
        local_96c0[lVar6] = *(int*)(DAT_18091b110 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(uint*)(local_8aa0 + lVar6 * 4) =
            local_9550[lVar6] * *(int*)((longlong)DAT_18091b130 + uVar15) +
            *(int*)((longlong)DAT_18091b150 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x128);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x128);
    lVar6 = 0;
    do {
        lVar12 = lVar6 + 1;
        uVar15 = (ulonglong)((uint)lVar12 & 7);
        uVar19 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(auStack364128 + lVar6 * 4) =
            (*(int*)(local_8aa0 + lVar6 * 4 + 4) * *(int*)(DAT_18091b170 + uVar15 * 4) +
                *(int*)(DAT_18091b190 + uVar15 * 4)) * *(int*)((longlong)DAT_18091b1b0 + uVar19) +
            *(int*)((longlong)DAT_18091b1d0 + uVar19);
        lVar6 = lVar12;
    } while (lVar12 != 0x49);
    *(uint*)(&auStack364128[292]) = 0xfb8ced37;
    local_80b0[36] =
        local_80b0[36] & 0xffffffffU |
        (ulonglong)(*(int *)local_8aa0 * -0x2c59b133 + 0x72ba05be) << 0x20;
    lVar6 = 0x48;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)((longlong)local_80b0 + lVar6 * 4) =
            *(int*)((longlong)DAT_18091b1f0 + uVar15) * 0x23831f90 +
            *(int*)((longlong)DAT_18091b210 + uVar15);
        bVar28 = lVar6 != 0;
        lVar6 = lVar6 + -1;
    } while (bVar28);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x128);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8f90 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091b230 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)((longlong)local_80b0 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b250 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(auStack364128 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b270 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    iVar46 = 0x20603285;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * -0x1f70482b + *(int*)(local_8f90 + lVar6 * 4);
        uVar45 = iVar21 * -0x7f019c87 + 0xb48ad856;
        *(uint *)local_a3b0 = uVar45;
        lVar12 = 0;

        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091b290 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[28]) * -0x23fa8edb + *(int*)(&local_a3b0[32]) * 0x3fa8edb0 + -0x13c91632;
        *(int*)(local_8390 + lVar6 * 4) =
            (iVar21 * 0x7361bf3d + *(int*)(&local_a3b0[28]) * -0x50000000 + 0x3cc85d12) *
            *(int*)((longlong)DAT_18091b2d0 + uVar15) + *(int*)((longlong)DAT_18091b2f0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    *(ulonglong*)local_9f60 = 0xd2cf473accfa60e7;
    local_9f60[2] = 0x8faf2311;
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x250);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 600);
    lVar12 = 0;
    *(ulonglong*)auStack364128 = 0;
    *(ulonglong*)local_9c80 = 0;
    lVar6 = 0;
    while (true) {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)local_8aa0 * *(int*)((longlong)DAT_18091b310 + uVar15) +
                *(int*)((longlong)DAT_18091b330 + uVar15)) * -0x65e8f2cf + 0xaa5fd503);
        uVar19 = uVar15 * 0x4784248b0da24959 + 0x262f5067f167424f;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091b350 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar19 * -0x5813bc8500000000 + uVar15 * -0x76ef9887b33788c3 + 0x22332d562b4d659d;
        local_80b0[lVar6] = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 0x4a) break;
        *(int*)local_8aa0 = *(int*)(local_8aa0 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    iVar46 = -0x33059f19;
    lVar12 = 0;
    lVar6 = 0;
    while (true) {
        uVar19 = (ulonglong)
            ((iVar46 * *(int*)((longlong)DAT_18091b3d0 + lVar6 * 4) +
                *(int*)((longlong)DAT_18091b3dc + lVar6 * 4)) * 0x4851924f + 0xd8d4c365);
        uVar15 = uVar19 * -0x2ded21f06d0f43c7 + 0xcc8b9916fb5cc185;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091b3f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x21dd3c2b00000000 + uVar19 * -0x7cee38a0f3e066d + -0x728331f0cfe71f58;
        *(longlong*)(local_9df0 + lVar6 * 8) = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(local_9c80 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 3) break;
        iVar46 = *(int*)((longlong)local_9f60 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    lVar6 = 0x4c8c55d6ec5bf913;
    uVar15 = 1;
    uVar19 = 0;
    do {
        uVar25 = (uint)uVar19;
        uVar45 = uVar25 - 2;
        if (uVar25 < 2) {
            uVar45 = 0;
        }
        uVar16 = (ulonglong)uVar45;
        uVar8 = uVar19 - uVar16;
        if (uVar16 <= uVar19) {
            lVar12 = 0;
            uVar7 = uVar16;
            do {
                lVar12 = lVar12 + *(longlong*)(local_9df0 + (uVar8 & 0xffffffff) * 8) * local_80b0[uVar7];
                uVar7 = uVar7 + 1;
                uVar8 = uVar8 - 1;
            } while (uVar15 != uVar7);
            uVar8 = (ulonglong)((uVar25 + 1) - uVar45);
            lVar6 = uVar8 * 0x51969dc63ad23878 + lVar6 + lVar12 * -0x69eca7e92cf11133 +
                (*(longlong*)(auStack364128 + uVar19 * 8 + 8) -
                    *(longlong*)(auStack364128 + uVar16 * 8)) * -0x385816bf4b82c8ae +
                *(longlong*)(local_9c80 + uVar8 * 8) * 0x5e18fac664796b2c;
        }
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar6 * -0x4b614008f39d85cf + 0x2645ef9d39803594;
        *(ulonglong *)local_8f90 = uVar8;
        lVar12 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091b470 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar12 * 8 + 8) = uVar8;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        iVar46 = (int)lVar6;
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x3309ed1000000000 + *(longlong*)(&local_8f90[56]) * -0x616741b95ccf612f +
            -0xd34a3085a7d15d4;
        uVar8 = (ulonglong)(uVar25 * 4 & 0x1c);
        *(int*)(local_8220 + uVar19 * 4) =
            (iVar46 * 0x2b9a966f + (int)*(longlong*)(&local_8f90[56]) * 0x10000000 + -0x61dd8291) *
            *(int*)((longlong)DAT_18091b4f0 + uVar8) + *(int*)((longlong)DAT_18091b510 + uVar8);
        uVar19 = uVar19 + 1;
        uVar15 = uVar15 + 1;
    } while (uVar19 != 0x4a);
    *(ulonglong *)local_9f60 = 0x5d8974c994711642;
    local_9f60[2] = 0xcbddcfaa;
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x250);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 600);
    lVar6 = 0;
    *(ulonglong*)auStack364128 = 0;
    *(ulonglong*)local_9c80 = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((*(int*)(local_8390 + lVar12 * 4) * *(int*)((longlong)DAT_18091b530 + uVar15) +
                *(int*)((longlong)DAT_18091b550 + uVar15)) * -0x6dd725a7 + 0xe48ff6ac);
        uVar15 = uVar19 * -0x4ee258320eecf581 + 0x98b51edd1d68fa4d;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091b570 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x3d8fbed900000000 + uVar19 * 0x1e8fe7366520d859 + 0x2d52d730ba0e9926;
        local_80b0[lVar12] = lVar20;
        lVar6 = lVar6 + lVar20;
        *(longlong*)(auStack364128 + lVar12 * 8 + 8) = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x4a);
    iVar46 = -0x6b8ee9be;
    lVar12 = 0;
    lVar6 = 0;
    while (true) {
        uVar19 = (ulonglong)
            ((iVar46 * *(int*)((longlong)DAT_18091b5f0 + lVar6 * 4) +
                *(int*)((longlong)DAT_18091b5fc + lVar6 * 4)) * -0x78e8f05d + 0x3cd26365);
        uVar15 = uVar19 * -0x7d52a18e4aa4d9dd + 0xad32ee0611bfdde;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091b610 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x47b40edd00000000 + uVar19 * 0x12b2e5411161d637 + -0x772c911cc8859c2e;
        *(longlong*)(local_9df0 + lVar6 * 8) = lVar20;
        lVar12 = lVar12 + lVar20;
        *(longlong*)(local_9c80 + lVar6 * 8 + 8) = lVar12;
        if (lVar6 + 1 == 3) break;
        iVar46 = *(int*)((longlong)local_9f60 + lVar6 * 4 + 4);
        lVar6 = lVar6 + 1;
    }
    lVar6 = 0x10f178e6ca1bfdc9;
    uVar15 = 1;
    uVar19 = 0;
    do {
        uVar25 = (uint)uVar19;
        uVar45 = uVar25 - 2;
        if (uVar25 < 2) {
            uVar45 = 0;
        }
        uVar16 = (ulonglong)uVar45;
        uVar8 = uVar19 - uVar16;
        if (uVar16 <= uVar19) {
            lVar12 = 0;
            uVar7 = uVar16;
            do {
                lVar12 = lVar12 + *(longlong*)(local_9df0 + (uVar8 & 0xffffffff) * 8) * local_80b0[uVar7];
                uVar7 = uVar7 + 1;
                uVar8 = uVar8 - 1;
            } while (uVar15 != uVar7);
            uVar8 = (ulonglong)((uVar25 + 1) - uVar45);
            lVar6 = uVar8 * 0x374ab4183c505ced + lVar6 + lVar12 * 0x2869788e5a772b55 +
                (*(longlong*)(auStack364128 + uVar19 * 8 + 8) -
                    *(longlong*)(auStack364128 + uVar16 * 8)) * -0x797b9efc0bbb8a79 +
                *(longlong*)(local_9c80 + uVar8 * 8) * 0x7350953e12b507;
        }
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar6 * 0x71487dd84a3e81cf + 0x605e9e7dee85412d;
        *(ulonglong*)local_8f90= uVar8;
        lVar12 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091b690 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar12 * 8 + 8) = uVar8;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x10);
        iVar46 = (int)lVar6;
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x718e52f000000000 + *(longlong*)(&local_8f90[56]) * -0x12fed6e998e71ad1 +
            0x5486d8aecb03c7bd;
        uVar8 = (ulonglong)(uVar25 * 4 & 0x1c);
        *(int*)(local_8500 + uVar19 * 4) =
            (iVar46 * 0x31990b25 + (int)*(longlong*)(&local_8f90[56]) * 0x50000000 + 0x1c34c973) *
            *(int*)((longlong)DAT_18091b710 + uVar8) + *(int*)((longlong)DAT_18091b730 + uVar8);
        uVar19 = uVar19 + 1;
        uVar15 = uVar15 + 1;
    } while (uVar19 != 0x4a);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x128);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8f90 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091b750 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(local_8220 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b770 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        *(int*)(local_8f90 + lVar6 * 4) =
            *(int*)(local_8f90 + lVar6 * 4) +
            *(int*)(local_8500 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091b790 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    iVar46 = 0x6124fd1d;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * -0x2f532b0f + *(int*)(local_8f90 + lVar6 * 4);
        uVar45 = iVar21 * 0x5811c417 + 0x14863962;
        *(uint *) local_a3b0 = uVar45;
        lVar12 = 0;
        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091b7b0 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[32]) * -0x3f5b2170 + *(int*)(&local_a3b0[28]) * 0x63f5b217 + 0x20a0ca2f;
        *(int*)(local_87d0 + lVar6 * 2) =
            (iVar21 * 0x60bc7f99 + *(int*)(&local_a3b0[28]) * 0x10000000 + -0x3b7b3c8) *
            *(int*)((longlong)DAT_18091b7f0 + uVar15) + *(int*)((longlong)DAT_18091b810 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        local_9830[lVar6] =
            *(int*)(local_87d0 + lVar6 * 2) * *(int*)((longlong)DAT_18091b830 + uVar15) +
            *(int*)((longlong)DAT_18091b850 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x4a);
    lVar6 = 0x4a;
    do {
        local_9830[lVar6] = *(int*)(DAT_18091b870 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_9c80, 0xaa, 0x168);
    Maybe_MEMSET_180512a50(local_9df0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_9f60, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a0d0, 0xaa, 0x168); //0x4ee00
    Maybe_MEMSET_180512a50((char*)local_a240, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x2d8);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d8);
    lVar6 = 0;
    *(ulonglong*)auStack364128 = 0;
    local_80b0[0] = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((*(int*)(p4_holder + lVar12 * 4) * *(int*)((longlong)DAT_18091b890 + uVar15) +
                *(int*)((longlong)DAT_18091b8b0 + uVar15)) * 0x56a33f0b + 0x390ebaee);
        uVar15 = uVar19 * 0x38e399f13dbc8823 + 0xde9e3cacc14c9275;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091b8d0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x3463b5eb00000000 + uVar19 * 0x6a17a8be462548df + -0xc4c9124eb9195a4;
        *(longlong*)(local_87d0 + lVar12 * 4) = lVar20;
        lVar6 = lVar6 + lVar20;
        *(longlong*)(auStack364128 + lVar12 * 8 + 8) = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar6 = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((*(int*)(local_res20 + lVar12 * 4) * *(int*)((longlong)DAT_18091b950 + uVar15) +
                *(int*)((longlong)DAT_18091b970 + uVar15)) * -0x2e9ff659 + 0x759685ef);
        uVar15 = uVar19 * -0x4fadd22aea905fff + 0x7d66980d784937a5;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091b990 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x18ec7a7900000000 + uVar19 * -0x3a63f0531310e587 + -0x4291ac1653d81cf0;
        *(longlong*)(local_8aa0 + lVar12 * 8) = lVar20;
        lVar6 = lVar6 + lVar20;
        local_80b0[lVar12 + 1] = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar6 = 0x41ce40f304168a8b;
    uVar15 = 0;
    do {
        plVar17 = (longlong*)local_87d0;
        lVar12 = 0;
        uVar19 = uVar15;
        do {
            lVar12 = lVar12 + *(longlong*)(local_8aa0 + (uVar19 & 0xffffffff) * 8) * *plVar17;
            plVar17 = plVar17 + 1;
            bVar28 = uVar19 != 0;
            uVar19 = uVar19 - 1;
        } while (bVar28);
        uVar19 = uVar15 + 1;
        lVar12 = uVar19 * -0x6e397d885ff961dc + lVar6 + lVar12 * -0x14ecd9917efe800f +
            *(longlong*)(auStack364128 + uVar15 * 8 + 8) * -0x4b1c3a8baa4f8f86 +
            local_80b0[uVar15 + 1] * 0x2946d6e5fcd02da;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar12 * -0x6699b5f3111f91af + 0xb709a151132e639f;
        *(ulonglong*)local_8f90 =  uVar8;
        lVar6 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091ba10 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar8;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        lVar6 = *(longlong*)(&local_8f90[128]) * 0x3b8654f000000000 + *(longlong*)(&local_8f90[56]) * -0x2dd47cb183b8654f +
            0x28b547772fe67911;
        uVar8 = (ulonglong)((int)uVar15 * 4 & 0x1c);
        local_99a0[uVar15] =
            ((int)*(longlong*)(&local_8f90[56]) * 0x70000000 + (int)lVar12 * 0x4b003b09 + -0x3b553ab1) *
            *(int*)((longlong)DAT_18091ba90 + uVar8) + *(int*)((longlong)DAT_18091bab0 + uVar8);
        uVar15 = uVar19;
    } while (uVar19 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    pbVar24 = p1_holder+ 0x2590; //0x168
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(uint*)(local_8220 + lVar6 * 4) =
            local_93e0[lVar6] * *(int*)((longlong)DAT_18091bad0 + uVar15) +
            *(int*)((longlong)DAT_18091baf0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            *(int*)(p4_holder + lVar6 * 4) * *(int*)((longlong)DAT_18091bb10 + uVar15) +
            *(int*)((longlong)DAT_18091bb30 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_96c0[lVar6] * *(int*)((longlong)DAT_18091bb50 + uVar15) +
            *(int*)((longlong)DAT_18091bb70 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)((longlong)local_9f60 + lVar6 * 4) =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091db90 + uVar15) +
            *(int*)((longlong)DAT_18091dbb0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8220 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091dbd0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            *(int*)((longlong)local_9f60 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091dbf0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            *(int*)(pbVar24 + lVar6 * 4 ) *
            *(int*)((longlong)DAT_18091dc10 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    iVar46 = 0x5183b995;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * 0xc940f5d + *(int*)(local_8220 + lVar6 * 4);
        uVar45 = iVar21 * 0x26935655 + 0x1c1c61bc;
        *(uint *)local_a3b0 = uVar45;
        lVar12 = 0;

        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091dc30 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[32]) * 0xded3df0 + *(int*)(&local_a3b0[28]) * -0x30ded3df + 0x433b6894;
        *(int*)(local_8390 + lVar6 * 4) =
            (iVar21 * -0x14e68cab + *(int*)(&local_a3b0[28]) * -0x10000000 + 0x13c57562) *
            *(int*)((longlong)DAT_18091dc70 + uVar15) + *(int*)((longlong)DAT_18091dc90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    var_st2 = *(longlong*)(p1_holder + 0xf18);
    pbVar23 = auStack364128;
    Maybe_MEMSET_180512a50((char*)pbVar23, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a5db2(local_8390, 0, (longlong*)local_87d0);
 
    ECCarry_1801a5e54(p1_holder + 0x2428, 0, (longlong*)local_8aa0);
    local_80b0[0] = *(longlong* )local_87d0;
    *(longlong*)local_8f90 = *(longlong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
    longlong tmpl= *(longlong*)local_87d0;
    do {
        ECCarry_1801a5db2(local_8390, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));
       
        tmpl = tmpl+ *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl= *(longlong*)local_8aa0;
    pbVar24 = p1_holder + 0x2428;
    do {
        ECCarry_1801a5e54(pbVar24, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        pbVar3 = p1_holder;
        tmpl = tmpl + *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = -0x41688c5d17156264;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4); 
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * 0x70d97d27c167f186 + -0x41688c5d17156264 +
                lVar6 * 0x6f7d4af7ea820217 + lVar12 * -0x2bb23c38c4585c7d +
                lVar20 * -0x1fe6bcd28df5cb52;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * 0x13675c4a8cbd63e9 + -0x7f375c8f82c70169;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(pbVar3 + lVar6 * 4 + 0xad8) * *(int*)((longlong)DAT_18091de30 + uVar15) +
                *(int*)((longlong)DAT_18091de50 + uVar15)) * 0x6af63eb5 + 0x83ee2954);
        uVar19 = uVar15 * 0x374329e55d41d41b + 0x5c3a3ba4fbf1f2d8;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091de70 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * -0x6e9176e300000000 + uVar15 * -0x49c98b9939917a0f + -0x1b604cf27412f3;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    longlong tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv *
            ((longlong)var_st2 * -0x58d0f05f0de56e4b + 0x2853526afcb99966) +
            (longlong)var_st2 * -0x107c3b0b9c76f3ef + 0xf388fe35d565fb9;
        uVar15 = lVar12 * 0x1b9cbeafba6ab311 + 0xdf08f3b4202eb3a1;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091def0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x2ae48b8d70000000 + lVar12 * 0x24d4005c2b189b47 + -0x1fc7c5217e456989;
        lVar12 = lVar20 * 0x45d72345fdb3c532 + -0x44cfe4114de90348;
        uVar15 = lVar20 * -0x3ae58f37e479f535 + 0xd9f051458c5d2f14;

        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar23 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar23[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar23[lVar20 * 8], xmm2.data, 16);

            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * -0x25c9f3958bccb89d + 0x5acb26097ef96b27;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091df70 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * 0x65d615f904ce3351 + 0x7fd170092a7ae1b;
        uVar15 = lVar12 * -0x6f9b7fdb4e3e18bd + 0x436b1d9263234d32;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091dff0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv  =
            (uVar15 * -0x5ac939d000000000 + lVar12 * 0x647bfb5a6bba4d17) * 0x490c20ad6267c0dd +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + -0x4c99e5c5af341480;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar23 = pbVar23 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = 0x234813280133c738;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * 0xe70862508118643 +
            lVar6 * -0x179e3070c7b5bfa9 + -0x17d42bf5cee802c1;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar15 = lVar20 * -0x4d2e685b11c08589 + 0x79eb51be509a2886;
        *(ulonglong *) local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e070 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * 0x55e5d6f000000000 + *(longlong*)(&local_8f90[56]) * 0x7fc907523aa1a291 +
            0x722c893389471212;
        // weird overlap between two stack variables. Probably decompiler error
        if (lVar12 * 8 + 2*0xb4 < 0x9d0 - 0x700)
        {
            *(int*)((longlong)local_87d0 + lVar12 * 2 + 0xb4) =
                ((int)*(longlong*)(&local_8f90[56]) * -0x70000000 + (int)lVar20 * 0x23b3dee1 + 0x143266d) *
                *(int*)((longlong)DAT_18091e0f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091e110 + uVar15 * 4);
        }
        else
        {
            *(int*)((longlong)local_8500 + lVar12 * 4 - 0xb4*2) =
                ((int)*(longlong*)(&local_8f90[56]) * -0x70000000 + (int)lVar20 * 0x23b3dee1 + 0x143266d) *
                *(int*)((longlong)DAT_18091e0f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091e110 + uVar15 * 4);
        }

        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    var_st2 = *(longlong*)(p1_holder + 0xf20);
    pbVar24 = p1_holder + 0x22c0;
    pbVar23 = auStack364128;
    Maybe_MEMSET_180512a50((char*)pbVar23, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a5ef6(local_8500, 0, (longlong*)local_87d0);
    pbStack364184 = pbVar24;
    ECCarry_1801a5f98(pbVar24, 0, (longlong*)local_8aa0);
    local_80b0[0] = *(longlong *)local_87d0;
    *(longlong*)local_8f90 = *(longlong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
     tmpl= *(longlong*)local_87d0;
    do {
        ECCarry_1801a5ef6(local_8500, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));
        pbVar24 = pbStack364184;
        tmpl = tmpl + *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl = *(longlong*)local_8aa0;
    do {
        ECCarry_1801a5f98(pbVar24, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        tmpl = tmpl + *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = -0x6be1fce3991cdaa6;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4);
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * -0x527aeac8c7f46e30 + -0x6be1fce3991cdaa6 +
                lVar6 * -0x3e4b9ca40d3c1baf + lVar12 * 0x2c89f536b92dfdb8 +
                lVar20 * 0x58f8b01b214f0276;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * -0x47a2a56e7e187111 + -0xec2d05d5d0f62ec;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(p1_holder + lVar6 * 4 + 0x100) *
                *(int*)((longlong)DAT_18091e2b0 + uVar15) +
                *(int*)((longlong)DAT_18091e2d0 + uVar15)) * 0x145bacd3 + 0x316cb1ea);
        uVar19 = uVar15 * 0x12996f559ca64503 + 0x8ef7c39acfd32bbb;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091e2f0 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * 0x1134768f00000000 + uVar15 * -0x3d617d9b5c4beead + 0x7b69ccc7b314dd8e;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv *
            ((longlong)var_st2 * 0x35c720ba6c83682f + 0x680da73a4ab609dc) +
            (longlong)var_st2 * -0x4d862b2ef65dacc6 + 0x27ea95408eb0306d;
        uVar15 = lVar12 * 0x33129a73b06a463d + 0xc4f843e4c45d9c9e;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e370 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x4fba11d5f0000000 + lVar12 * 0x3797b34d833e065d + -0x1e4fd43aa0990bee;
        lVar12 = lVar20 * 0x3250f28ec2556607 + 0x17cc917f927cea8b;
        uVar15 = lVar20 * -0x2f1c04ce064cf7e9 + 0x799efcda7daa2a5b;
        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar23 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar23[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar23[lVar20 * 8], xmm2.data, 16);

            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * 0x7b9cc1bb1f278191 + 0x487be9d5a8c5da49;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e3f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * 0x2c1d502631ab4531 + -0x587931e5f49cf92a;
        uVar15 = lVar12 * 0x3f3f1a4b6f33c5a1 + 0xdf319f462791d94b;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e470 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv =
            (uVar15 * 0x51eb06f000000000 + lVar12 * -0x2538bc65bd2f60cf) * 0x548bc86294505c11 +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + 0x304e7217079d3c63;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar23 = pbVar23 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = -0x4ca132e180fab1b3;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * -0x4e0f1aa6c168523b +
            lVar6 * 0x112fe57ca3d2a873 + -0x50cbcd3bde1cca34;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar15 = lVar20 * -0x329cb31c9ec1ac43 + 0x66843917ad750fb8;
        *(ulonglong *)local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e4f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x78d9dd7000000000 + *(longlong*)(&local_8f90[56]) * -0x4acbde0688726229 +
            0x27a599e11a944fe;
        if (0x4eb28+lVar12 * 4 < 0x4ec90)
        {
            *(int*)(local_a3b0 + lVar12 * 4 + 8) =
                ((int)*(longlong*)(&local_8f90[56]) * 0x70000000 + (int)lVar20 * -0x3df3bc1b + 0x54e12138) *
                *(int*)((longlong)DAT_18091e570 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091e590 + uVar15 * 4);
        }
        else
        {
            //0x4eb28=a3b0+8, 4ec90 - local_a240
            *(int*)((longlong)local_a240 + lVar12 * 4+ 0x4eb28- 0x4ec90) =
                ((int)*(longlong*)(&local_8f90[56]) * 0x70000000 + (int)lVar20 * -0x3df3bc1b + 0x54e12138) *
                *(int*)((longlong)DAT_18091e570 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091e590 + uVar15 * 4);
        }
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    var_stack = *(longlong *)(p1_holder + 0xf20);
    pbVar24 = p1_holder + 0x1230;
    pbVar23 = auStack364128;
    Maybe_MEMSET_180512a50((char*)pbVar23, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a603a((byte *)local_a240, 0, (longlong*)local_87d0);
    byte * tmpb = pbVar24;
    ECCarry_1801a60dc(pbVar24, 0, (longlong*)local_8aa0);
    local_80b0[0] = *(longlong *)local_87d0;
    *(longlong*)local_8f90 = *(longlong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
    tmpl= *(longlong*)local_87d0;
    do {
        ECCarry_1801a603a((byte *)local_a240, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));

        tmpl = tmpl + *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl=*(longlong*)local_8aa0;
    do {
        ECCarry_1801a60dc(pbVar24, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        tmpl= tmpl+ *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = -0x4d73ee3594c58102;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4);
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * 0x3ebedd068af224c9 + -0x4d73ee3594c58102 +
                lVar6 * 0x1e085f47ff31dbc9 + lVar12 * -0x37f7c01a8bdc3e51 +
                lVar20 * 0x5ff57330a813f17f;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * 0x2cc8f44f676bf68d + -0x51b7fbae44eba6a1;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(p1_holder + lVar6 * 4 + 0x100) *
                *(int*)((longlong)DAT_18091e730 + uVar15) +
                *(int*)((longlong)DAT_18091e750 + uVar15)) * 0x14e6cb43 + 0xcfa75f96);
        uVar19 = uVar15 * 0x1c1089138c2116e5 + 0xcd1cec722c0c32ff;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091e770 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * -0x529ef82f00000000 + uVar15 * -0x4c6ca6ffbc68f3f5 + -0x63f43a24daf8cf31;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv *
            ((longlong)var_stack * -0x57028d825543690f + -0x399065d3999ed15c) +
            (longlong)var_stack * 0x3bb59346ce89e20b + -0xd5705ad57744a29;
        uVar15 = lVar12 * 0x4632f10c8cf67a9 + 0x69dea052b7e3cdc9;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e7f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x762926d230000000 + lVar12 * -0x40131c4293e0211b + 0x31aea4c75bae143a;
        lVar12 = lVar20 * -0x143ff62903f4e140 + -0x75375ab1652a0ac0;
        uVar15 = lVar20 * -0x7d446d60ce83f177 + 0xe4b2c62363cd4ce7;
        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar23 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar23[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar23[lVar20 * 8], xmm2.data, 16);
            
            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * 0x7a09c8d3c780c093 + 0x42c3203341affa5b;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e870 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * -0x574ed42fcbfd280b + -0x31df93da420a1958;
        uVar15 = lVar12 * -0x4880331d13877f25 + 0xcb0026072e923c5c;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e8f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv =
            (uVar15 * 0x2007ae5000000000 + lVar12 * -0x7ac0cbda2b33a1e7) * -0x5143989e6b1a3459 +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + -0x585752799b98563d;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar23 = pbVar23 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = 0x7fa5d656fb0923d4;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * -0x749e2e1c1ab3afff +
            lVar6 * -0x2de4a2aeb916d89f + 0x7543160ffadfaa9f;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar15 = lVar20 * 0x1f0388318a16aac5 + 0xb3b0fba035ca32b2;
        *(ulonglong*)local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091e970 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * 0x2aba7d3000000000 + *(longlong*)(&local_8f90[56]) * -0x3e88b670a2aba7d3 +
            -0x25ef7ca3e8af51ae;
        ;

        if (lVar12 * 4 >= 0x168)
        {
            *(int*)((longlong )local_a0d0+ lVar12 * 4- 0x168) =
                ((int)*(longlong*)(&local_8f90[56]) * -0x30000000 + (int)lVar20 * -0x249b6d21 + -0x32c15857) *
                *(int*)((longlong)DAT_18091e9f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091ea10 + uVar15 * 4);
        }
        else
        {
            local_a240[lVar12 + 2] =
                ((int)*(longlong*)(&local_8f90[56]) * -0x30000000 + (int)lVar20 * -0x249b6d21 + -0x32c15857) *
                *(int*)((longlong)DAT_18091e9f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091ea10 + uVar15 * 4);
        }
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x2d8);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d8);
    lVar6 = 0;
    *(ulonglong*)auStack364128 = 0;
    local_80b0[0] = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((local_96c0[lVar12] * *(int*)((longlong)DAT_18091ea30 + uVar15) +
                *(int*)((longlong)DAT_18091ea50 + uVar15)) * -0x5f9fc651 + 0xcde37476);
        uVar15 = uVar19 * -0x66d15db68712f53 + 0x2470daa23870538d;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) +
                *(longlong*)((longlong)DAT_18091ea70 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0x5605f10900000000 + uVar19 * -0x7cfc4ba90826cceb + -0x30653c163173e2d3;
        *(longlong*)(local_87d0 + lVar12 * 4) = lVar20;
        lVar6 = lVar6 + lVar20;
        *(longlong*)(auStack364128 + lVar12 * 8 + 8) = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar6 = 0;
    lVar12 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar12 * 4 & 0x1c);
        uVar19 = (ulonglong)
            ((local_9830[lVar12] * *(int*)((longlong)DAT_18091eaf0 + uVar15) +
                *(int*)((longlong)DAT_18091eb10 + uVar15)) * -0x38c8f447 + 0x8043b9b1);
        uVar15 = uVar19 * -0x7f13785dac081b89 + 0x23c00aaa2cd1e084;
        iVar46 = 8;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091eb30 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * -0xceb16a500000000 + uVar19 * 0x70c42e9db9a57ab3 + -0x6a6e37eca055139c;
        *(longlong*)(local_8aa0 + lVar12 * 8) = lVar20;
        lVar6 = lVar6 + lVar20;
        local_80b0[lVar12 + 1] = lVar6;
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0x5a);
    lVar6 = 0x5f18099f0837eaf8;
    uVar15 = 0;
    do {
        plVar17 = (longlong*)local_87d0;
        lVar12 = 0;
        uVar19 = uVar15;
        do {
            lVar12 = lVar12 + *(longlong*)(local_8aa0 + (uVar19 & 0xffffffff) * 8) * *plVar17;
            plVar17 = plVar17 + 1;
            bVar28 = uVar19 != 0;
            uVar19 = uVar19 - 1;
        } while (bVar28);
        uVar19 = uVar15 + 1;
        lVar12 = uVar19 * -0x74dddebd67a68df6 + lVar6 + lVar12 * -0x59bdff7374ab4bcd +
            *(longlong*)(auStack364128 + uVar15 * 8 + 8) * 0x77aaa6b8ae9617b7 +
            local_80b0[uVar15 + 1] * 0x7139be9dfa53f2;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar8 = lVar12 * 0x7d8a9e91a4416e0b + 0x64e95e6169d396f4;
        *(ulonglong *)local_8f90 = uVar8;
        lVar6 = 0;
        do {
            uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_18091ebb0 + (ulonglong)((uint)uVar8 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar8;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x5d2da3000000000 + *(longlong*)(&local_8f90[56]) * -0x4aa23fa2fa2d25d +
            0x2a718e575619fea4;
        uVar8 = (ulonglong)((int)uVar15 * 4 & 0x1c);
        local_9b10[uVar15] =
            ((int)*(longlong*)(&local_8f90[56]) * 0x70000000 + (int)lVar12 * -0x3d54d8ad + -0x62c4ff6c) *
            *(int*)((longlong)DAT_18091ec30 + uVar8) + *(int*)((longlong)DAT_18091ec50 + uVar8);
        uVar15 = uVar19;
    } while (uVar19 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    pbVar24 = p1_holder;
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8220 + lVar6 * 4) =
            local_a0d0[lVar6] * *(int*)((longlong)DAT_18091ec70 + uVar15) +
            *(int*)((longlong)DAT_18091ec90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            local_99a0[lVar6] * *(int*)((longlong)DAT_18091ecb0 + uVar15) +
            *(int*)((longlong)DAT_18091ecd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_9b10[lVar6] * *(int*)((longlong)DAT_18091ecf0 + uVar15) +
            *(int*)((longlong)DAT_18091ed10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_9c80 + lVar6 * 4) =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091ed30 + uVar15) +
            *(int*)((longlong)DAT_18091ed50 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8220 + lVar6 * 4) =
            local_a240[lVar6] * *(int*)((longlong)DAT_18091ed70 + uVar15) +
            *(int*)((longlong)DAT_18091ed90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            local_99a0[lVar6] * *(int*)((longlong)DAT_18091ecb0 + uVar15) +
            *(int*)((longlong)DAT_18091ecd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_9b10[lVar6] * *(int*)((longlong)DAT_18091ecf0 + uVar15) +
            *(int*)((longlong)DAT_18091ed10 + uVar15);//4f3c0
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_9df0 + lVar6 * 4) =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091edb0 + uVar15) +
            *(int*)((longlong)DAT_18091edd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_9f60, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a0d0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a240, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a3b0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a520, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(uint*)(local_8220 + lVar6 * 4) =
            local_9550[lVar6] * *(int*)((longlong)DAT_18091edf0 + uVar15) +
            *(int*)((longlong)DAT_18091ee10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            *(int*)(local_res20 + lVar6 * 4) * *(int*)((longlong)DAT_18091ee30 + uVar15) +
            *(int*)((longlong)DAT_18091ee50 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_9830[lVar6] * *(int*)((longlong)DAT_18091ee70 + uVar15) +
            *(int*)((longlong)DAT_18091ee90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        local_a240[lVar6] =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091eeb0 + uVar15) +
            *(int*)((longlong)DAT_18091eed0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168); //0x50cb0 local_8390
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8220 + lVar6 * 4) =
            local_a240[lVar6] * *(int*)((longlong)DAT_18091eef0 + uVar15) +
            *(int*)((longlong)DAT_18091ef10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    var_stack = *(longlong *)(pbVar24 + 0xf18);
    pbVar24 = auStack364128;
    Maybe_MEMSET_180512a50((char*)pbVar24, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a617e(local_8220, 0, (longlong*)local_87d0);
    ECCarry_1801a6220(p1_holder + 0x2428, 0, (longlong*)local_8aa0);
    local_80b0[0] = *(longlong*)local_87d0;
    *(longlong*)local_8f90 = *(longlong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
    tmpl = *(longlong*)local_87d0;
    do {
        ECCarry_1801a617e(local_8220, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));
        pbVar23 = p1_holder + 0x2428;
        tmpl= tmpl + *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl= *(longlong*)local_8aa0;
    do {
        ECCarry_1801a6220(pbVar23, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        tmpl= tmpl + *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = 0x2d76da429cef0967;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4);
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * -0x59c7ecc029ed84da + 0x2d76da429cef0967 +
                lVar6 * -0x560a42c24bc18349 + lVar12 * 0x288dddbeb0545287 +
                lVar20 * 0x24a88c740828b706;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * 0x41f2fcd9e5d39a91 + -0x2410b01838eece7c;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(p1_holder + lVar6 * 4 + 0xad8) *
                *(int*)((longlong)DAT_18091f0b0 + uVar15) +
                *(int*)((longlong)DAT_18091f0d0 + uVar15)) * -0x6e76686d + 0xe28a6324);
        uVar19 = uVar15 * -0x1ebd9c83b8c9b795 + 0x4320812481521ae;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091f0f0 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * 0x31706b9500000000 + uVar15 * -0x54d3da994cacdf47 + 0x7845696e37fbad45;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv *
            ((longlong)var_stack * 0x369bfb6c9403ef03 + 0x7c038186ca9b4aa) +
            (longlong)var_stack * -0x7cb2c3e1684ae591 + 0xd6e086482cc92c3;
        uVar15 = lVar12 * -0x3a23da2e2ef8f71f + 0x1a85f6f595ad48f3;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f170 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x58c737f610000000 + lVar12 * 0x2ba2d99445db03bf + -0x3b7fdc7152f22178;
        lVar12 = lVar20 * 0x18216384d6d191a + -0x279724812a04d556;
        uVar15 = lVar20 * -0xae91b9b12b82b1f + 0x887b52591086adc9;
        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);
        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar24 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar24[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar24[lVar20 * 8], xmm2.data, 16);
            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * -0x46bf0f8616e1a4e1 + 0xc5e235239c5c9cab;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f1f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * 0x3f4e8349a48c867f + -0x7471cc305a8096d7;
        uVar15 = lVar12 * -0x39f254839bd20c8d + 0x33c83916545aa8a0;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f270 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv =
            (uVar15 * -0x20b1833000000000 + lVar12 * -0x104922a52014b817) * -0x721dcd7b8129db07 +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + 0x19206660c8b705d1;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar24 = pbVar24 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = -0x3e2c74597ab16e4;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * -0x1d80d58a6d715af5 +
            lVar6 * 0x3b0e1085c64bafb9 + -0x72cda9b7f45917f8;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        pbVar24 = p1_holder;
        uVar15 = lVar20 * -0x696d1a3ce5bb5e59 + 0xd0850180d2a70c8f;
        *(ulonglong* )local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f2f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x5ca9c4f000000000 + *(longlong*)(&local_8f90[56]) * -0x4a6fd63c2a3563b1 +
            -0x4cd63f39af2d8c9a;
        if (lVar12 * 4>=0x168)
        {
            *(int*)(local_8390+ lVar12 * 4-0x168)= ((int)*(longlong*)(&local_8f90[56]) * 0x10000000 + (int)lVar20 * -0x5498cc67 + 0x62ea8232) *
                *(int*)((longlong)DAT_18091f370 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091f390 + uVar15 * 4);
        }
        else
        {
            *(int*)(local_8500 + lVar12 * 4 + 8) =
                ((int)*(longlong*)(&local_8f90[56]) * 0x10000000 + (int)lVar20 * -0x5498cc67 + 0x62ea8232) *
                *(int*)((longlong)DAT_18091f370 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091f390 + uVar15 * 4);
        }
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    longlong var_st3 = *(longlong*)(p1_holder + 0xf20);
    pbVar23 = auStack364128;
    Maybe_MEMSET_180512a50((char*)pbVar23, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a62c2(local_8390, 0, (longlong*)local_87d0); //local_8390 is offset? 
    ECCarry_1801a6364(pbStack364184, 0, (longlong*)local_8aa0);
    local_80b0[0] = *(ulonglong *)local_87d0;
    *(ulonglong*)local_8f90 = *(ulonglong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
    tmpl= *(ulonglong*)local_87d0;
    do {
        ECCarry_1801a62c2(local_8390, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));
        pbVar3 = pbStack364184;
        tmpl = tmpl+ *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl = *(ulonglong*)local_8aa0;
    do {
        ECCarry_1801a6364(pbVar3, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        tmpl = tmpl + *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = 0x3fb9b303ba962b40;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4);
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * -0xe09d5e6f3b5d0e0 + 0x3fb9b303ba962b40 +
                lVar6 * 0x51467452313a633d + lVar12 * 0x1b584c44e0cf55c + lVar20 * 0x45bd2e0c738cbd98;
            pbVar24 = p1_holder;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * 0x423df91c9df9e36f + -0x4f9ca8ed3f54e4b0;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(pbVar24 + lVar6 * 4 + 0x100) * *(int*)((longlong)DAT_18091f530 + uVar15) +
                *(int*)((longlong)DAT_18091f550 + uVar15)) * 0x2c3ffd31 + 0x5187d134);
        uVar19 = uVar15 * -0x4d2ae7d81eafae91 + 0xd9f581c9931c4d6a;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091f570 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * 0x7d2b363700000000 + uVar15 * 0x200b52bac5ec1727 + 0x12645df636ef3674;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv*
            ((longlong)var_st3 * -0x2589eacea96c0b2b + 0x35a4adac4c33cdb4) +
            (longlong)var_st3 * -0x69a1b638cc261950 + 0x5deb3f3db0a5a1d9;
        uVar15 = lVar12 * -0x1674632509c1608f + 0x1d7778ebb6b6cfc0;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f5f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0xb07d37eb0000000 + lVar12 * 0x4aaf6eb6f6155c45 + -0xb9a0cfd480eead5;
        lVar12 = lVar20 * 0x5739189374974d26 + -0x22928e781b783a70;
        uVar15 = lVar20 * 0x4af3f3485d431797 + 0x62581c989c909728;
        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);

        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar23 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar23[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar23[lVar20 * 8], xmm2.data, 16);

            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * -0x2c4aa1fd545dae7b + 0x5eadb7fa6f44e361;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f670 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * 0x204c511b8e821f3b + -0x736d4a63a31496d0;
        uVar15 = lVar12 * 0x4c5940cc2bf85807 + 0x768f52beb82d717b;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f6f0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv =
            (uVar15 * -0x40ac2f5000000000 + lVar12 * 0x7c06ce8b3a78cb3) * 0x3a51c64bcb3a2a0d +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + 0x26481cfe11cb6186;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar23 = pbVar23 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = 0x7d64020b577845a9;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * 0x1ec7a680bf7df8c5 +
            lVar6 * -0x4e2eb102fef562e9 + 0x483dd12cda0d34ba;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar15 = lVar20 * 0x593480e61eb5fd23 + 0x73ae3250ed9e024d;
        *(ulonglong *)local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091f770 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * -0x2e8dead000000000 + *(longlong*)(&local_8f90[56]) * -0x75e4386e6d172153 +
            -0x65a293b408e9398f;
        //0x4e848 aiStack42632
        //4e9b0
        if (lVar12 * 4 < 0x168)
        {
            aiStack42632[lVar12] =
                ((int)*(longlong*)(&local_8f90[56]) * -0x50000000 + (int)lVar20 * -0xb3cb101 + -0x780afde2) *
                *(int*)((longlong)DAT_18091f7f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091f810 + uVar15 * 4);
        }
        else
        {
            local_a520[lVar12-(0x168/4)] =
                ((int)*(longlong*)(&local_8f90[56]) * -0x50000000 + (int)lVar20 * -0xb3cb101 + -0x780afde2) *
                *(int*)((longlong)DAT_18091f7f0 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091f810 + uVar15 * 4);
        }
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    pbStack364184 = *(byte**)(p1_holder + 0xf20);
    pbVar23 = auStack364128;
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    ECCarry_1801a6406((byte *)local_a520, 0, (longlong*)local_87d0);
    ECCarry_1801a64a8(p1_holder+ 0x1230, 0, (longlong*)local_8aa0);// 0x1230
    local_80b0[0] = *(longlong*)local_87d0;
    *(longlong*) local_8f90 = *(longlong*)local_8aa0;
    lVar6 = 1;
    lVar12 = 8;
    tmpl = *(longlong*)local_87d0;
    do {
        ECCarry_1801a6406((byte *)local_a520, (uint)lVar6, (longlong*)((longlong)local_87d0 + lVar12));
        pbVar3 = pbVar24;
        tmpl = tmpl + *(longlong*)(local_87d0 + lVar6 * 4);
        local_80b0[lVar6] = tmpl;
        lVar6 = lVar6 + 1;
        lVar12 = lVar12 + 8;
    } while (lVar6 != 0x5a);
    lVar12 = 1;
    lVar6 = 8;
    tmpl = *(longlong*)local_8aa0;
    do {
        ECCarry_1801a64a8(p1_holder + 0x1230, (uint)lVar12, (longlong*)(local_8aa0 + lVar6));
        tmpl = tmpl+ *(longlong*)(local_8aa0 + lVar12 * 8);
        *(ulonglong*)(local_8f90 + lVar12 * 8) = tmpl;
        lVar12 = lVar12 + 1;
        lVar6 = lVar6 + 8;
    } while (lVar12 != 0x5a);
    uVar15 = 0;
    do {
        uVar19 = 0x59;
        if (uVar15 < 0x59) {
            uVar19 = uVar15;
        }
        uVar45 = (uint)uVar15;
        uVar8 = (ulonglong)(uVar45 - 0x59);
        if (uVar45 < 0x59) {
            uVar8 = 0;
        }
        lVar6 = -0xdcb6ec9e75918a3;
        uVar25 = (uint)uVar19;
        uVar27 = (uint)uVar8;
        if (uVar27 <= uVar25) {
            uVar16 = uVar15 - uVar8;
            lVar6 = 0;
            do {
                lVar6 = lVar6 + *(longlong*)(local_8aa0 + (uVar16 & 0xffffffff) * 8) *
                    *(longlong*)(local_87d0 + uVar8 * 4);
                uVar8 = uVar8 + 1;
                uVar16 = uVar16 - 1;
            } while (uVar19 + 1 != uVar8);
            lVar12 = local_80b0[uVar19];
            if (0x59 < uVar15) {
                lVar12 = lVar12 - local_80b0[uVar27 - 1];
            }
            lVar20 = *(longlong*)(local_8f90 + (ulonglong)(uVar45 - uVar27) * 8);
            if (0x59 < uVar15) {
                lVar20 = lVar20 - *(longlong*)(local_8f90 + (ulonglong)(~uVar25 + uVar45) * 8);
            }
            lVar6 = (ulonglong)((uVar25 - uVar27) + 1) * -0x2a7601c401cc390a + -0xdcb6ec9e75918a3 +
                lVar6 * -0x2d97d409eb8aabad + lVar12 * 0x299a527e34c8983f +
                lVar20 * -0x79e9d24d1025fa42;
            pbVar24 = p1_holder;
        }
        *(longlong*)(auStack364128 + uVar15 * 8) = lVar6 * 0x1f830a84ccd7f539 + 0x187fe3a5cc57a808;
        uVar15 = uVar15 + 1;
    } while (uVar15 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((*(int*)(pbVar24 + lVar6 * 4 + 0x100) * *(int*)((longlong)DAT_18091f9b0 + uVar15) +
                *(int*)((longlong)DAT_18091f9d0 + uVar15)) * 0x70302a91 + 0x9c9b2df6);
        uVar19 = uVar15 * 0x265e79e908280eb + 0xc8eb7c4c998ffc31;
        iVar46 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091f9f0 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        *(ulonglong*)(local_87d0 + lVar6 * 4) =
            uVar19 * 0x3f4a7c8300000000 + uVar15 * -0x3eeb82904227cc41 + 0x7d97ca8f4da6f7eb;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    tempqv = *(longlong*)auStack364128;
    do {
        lVar12 = tempqv *
            ((longlong)pbStack364184 * -0x1d71ee13f727961 + -0x4f3f409eafd2da64) +
            (longlong)pbStack364184 * 0x67b58e48bf68489d + 0xc5f3481321c199f;
        uVar15 = lVar12 * -0x28aaba17add87885 + 0x4ce48c15194453e8;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091fa70 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar20 = uVar15 * 0x7bc817f530000000 + lVar12 * 0x4f4fdd9527fe0e1f + -0x5936a54a5931fa71;
        lVar12 = lVar20 * -0x2081bc764a5e194c + 0x14879726070f52b0;
        uVar15 = lVar20 * -0x6f3752d085a1d89d + 0xa7e9b8eef3cfd514;
 
        xmm0.assign8(uVar15);
        xmm0.PSHUFD(xmm0, 0x44);
        xmm1.assign8(lVar12);
        xmm1.PSHUFD(xmm1, 0x44);

        lVar20 = 0;
        do {
            uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
            uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
            lVar2 = *(longlong*)((longlong)(pbVar23 + lVar20 * 8) + 8);
            memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
            memcpy(xmm3.data, &pbVar23[lVar20 * 8], 16);
            xmm3.PADDQ(xmm1);
            memcpy(xmm4.data, xmm0.data, 16);
            xmm4.PSRLQ(0x20);
            xmm4.PMULUDQ(xmm2);
            memcpy(xmm5.data, xmm2.data, 16);
            xmm5.PSRLQ(0x20);
            xmm5.PMULUDQ(xmm0);
            xmm5.PADDQ(xmm4);
            xmm5.PSLLQ(0x20);
            xmm2.PMULUDQ(xmm0);
            xmm2.PADDQ(xmm5);
            xmm2.PADDQ(xmm3);
            memcpy(&pbVar23[lVar20 * 8], xmm2.data, 16);

            lVar20 = lVar20 + 2;
        } while (lVar20 != 0x5a);
        uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * -0x2eeba6e08a46bc39 + 0xdf6bf4ab294c5421;
        iVar46 = 7;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091faf0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        lVar12 = uVar15 * 0x31b108a4115ba489 + 0x5830b665578b1d4d;
        uVar15 = lVar12 * -0x7fee0c99c110bf9b + 0xafa173e9a60eb66a;
        iVar46 = 9;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091fb70 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            iVar46 = iVar46 + -1;
        } while (iVar46 != 0);
        tempqv =
            (uVar15 * -0x415efe1000000000 + lVar12 * 0x39a95faf79aee3c5) * 0x11fd0e3c68a2c973 +
            *(longlong*)(auStack364128 + lVar6 * 8 + 8) + 0xb69f5c5bcb88541;
        *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
        lVar6 = lVar6 + 1;
        pbVar23 = pbVar23 + 8;
    } while (lVar6 != 0x5a);
    lVar6 = -0x2ffd506036969a32;
    lVar12 = 0x5a;
    do {
        lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * -0x47d977f8edba1871 +
            lVar6 * 0x710e1d9d0857a6c1 + -0x3169b83b7c969dd1;
        Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
        uVar15 = lVar20 * -0x554cfe1ccedc3d87 + 0xe45120224d2e9208;
        *(ulonglong *)local_8f90 = uVar15;
        lVar6 = 0;
        do {
            uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_18091fbf0 + (ulonglong)((uint)uVar15 & 0xf) * 8);
            *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
            lVar6 = lVar6 + 1;
        } while (lVar6 != 0x10);
        uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
        lVar6 = *(longlong*)(&local_8f90[128]) * 0x4b414f7000000000 + *(longlong*)(&local_8f90[56]) * 0x439e1cedcb4beb09 +
            -0x251f824fbaa9a78a;
        if (lVar12 * 4 < 0x168)
        {
            local_a520[lVar12 + 2] =
                ((int)*(longlong*)(&local_8f90[56]) * 0x30000000 + (int)lVar20 * 0x7b68c725 + -0xbb6d2d0) *
                *(int*)((longlong)DAT_18091fc70 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091fc90 + uVar15 * 4);
        }
        else
        {
            *(int*)((longlong)local_a3b0+ lVar12 * 4- 0x168)= ((int)*(longlong*)(&local_8f90[56]) * 0x30000000 + (int)lVar20 * 0x7b68c725 + -0xbb6d2d0) *
                *(int*)((longlong)DAT_18091fc70 + uVar15 * 4) +
                *(int*)((longlong)DAT_18091fc90 + uVar15 * 4);
        }
        lVar12 = lVar12 + 1;
    } while (lVar12 != 0xb4);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    pbVar24 = p1_holder;
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_a3b0 + lVar6 * 4) * *(int*)((longlong)DAT_18091fcb0 + uVar15) +
            *(int*)((longlong)DAT_18091fcd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0; //checked...
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            local_99a0[lVar6] * *(int*)((longlong)DAT_18091ecb0 + uVar15) +
            *(int*)((longlong)DAT_18091ecd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_9b10[lVar6] * *(int*)((longlong)DAT_18091ecf0 + uVar15) +
            *(int*)((longlong)DAT_18091ed10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)((longlong)local_9f60 + lVar6 * 4) =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091fcf0 + uVar15) +
            *(int*)((longlong)DAT_18091fd10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a); 
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8390, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8500, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x168);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8220 + lVar6 * 4) =
            local_a520[lVar6] * *(int*)((longlong)DAT_18091fd30 + uVar15) +
            *(int*)((longlong)DAT_18091fd50 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8390 + lVar6 * 4) =
            local_99a0[lVar6] * *(int*)((longlong)DAT_18091ecb0 + uVar15) +
            *(int*)((longlong)DAT_18091ecd0 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        *(int*)(local_8500 + lVar6 * 4) =
            local_9b10[lVar6] * *(int*)((longlong)DAT_18091ecf0 + uVar15) +
            *(int*)((longlong)DAT_18091ed10 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Shufflemul_1801a34a5(local_8220, local_8390, local_8500, (int*)auStack364128);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        local_a0d0[lVar6] =
            *(int*)(auStack364128 + lVar6 * 4) * *(int*)((longlong)DAT_18091fd70 + uVar15) +
            *(int*)((longlong)DAT_18091fd90 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8220 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091fdb0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            *(int*)(local_9c80 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091fdd0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            *(int*)((longlong)local_9f60 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091fdf0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1; 
    } while (lVar6 != 0x5a);
    iVar46 = -0x505f5473;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * -0x6ed569b7 + *(int*)(local_8220 + lVar6 * 4);
        uVar45 = iVar21 * 0x7656d8ad + 0x954adf79;
        *(uint *)local_a3b0 =uVar45;
        lVar12 = 0;
 
        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091fe10 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[28]) * -0x73206203 + *(int*)(&local_a3b0[32]) * 0x32062030 + 0x38516c0;
        local_9100[lVar6] =
            (iVar21 * 0x5bd1b03f + *(int*)(&local_a3b0[28]) * 0x50000000 + 0x73c0d490) *
            *(int*)((longlong)DAT_18091fe50 + uVar15) + *(int*)((longlong)DAT_18091fe70 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8220, 0xaa, 0x168);
    lVar6 = 0;
    do {
        *(undefined4*)(local_8220 + lVar6 * 4) =
            *(undefined4*)((longlong)DAT_18091fe90 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            *(int*)(local_9df0 + lVar6 * 4) *
            *(int*)((longlong)DAT_18091feb0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(int*)(local_8220 + lVar6 * 4) =
            *(int*)(local_8220 + lVar6 * 4) +
            local_a0d0[lVar6] * *(int*)((longlong)DAT_18091fed0 + (ulonglong)((uint)lVar6 & 7) * 4);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    iVar46 = -0x14d11b2f;
    lVar6 = 0;
    do {
        iVar21 = iVar46 * -0x530118dd + *(int*)(local_8220 + lVar6 * 4);
        uVar45 = iVar21 * 0x5dcbfbaf + 0x664ad55a;
        *(uint *)local_a3b0 =  uVar45;
        lVar12 = 0;

        do {
            uVar45 = (uVar45 >> 4) + *(int*)(DAT_18091fef0 + (ulonglong)(uVar45 & 0xf) * 4);
            *(uint*)(local_a3b0 + lVar12 * 4 + 4) = uVar45;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 8);
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        iVar46 = *(int*)(&local_a3b0[28]) * -0x5b394c1b + *(int*)(&local_a3b0[32]) * -0x4c6b3e50 + 0x6b6afd34;
        local_9270[lVar6] =
            (iVar21 * -0x11162bcb + *(int*)(&local_a3b0[28]) * 0x50000000 + 0x3a9ae6eb) *
            *(int*)((longlong)DAT_18091ff30 + uVar15) + *(int*)((longlong)DAT_18091ff50 + uVar15);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)local_8aa0, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x2d0);
    Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
    lVar6 = 0;
    do {
        uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
        uVar15 = (ulonglong)
            ((local_9100[lVar6] * *(int*)((longlong)DAT_18091ff70 + uVar15) +
                *(int*)((longlong)DAT_18091ff90 + uVar15)) * 0x157d9841 + 0xb7acb29f);
        uVar19 = uVar15 * 0x187ad213f2e15a7d + 0xf55b14120c9be19;
        iVar22 = 8;
        do {
            uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_18091ffb0 + (ulonglong)((uint)uVar19 & 0xf) * 8);
            iVar22 = iVar22 + -1;
        } while (iVar22 != 0);
        *(ulonglong*)(local_8f90 + lVar6 * 8) =
            uVar19 * 0x385491ab00000000 + uVar15 * -0x5900a740e9cc3e7f + 0xfc57e12b81652b6;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    lVar6 = 0;
    do {
        *(longlong*)(local_87d0 + lVar6 * 4) =
            *(longlong*)(local_8f90 + lVar6 * 8) * 0x1d822898d3d75c1b + -0x5ee232e7b9b7db57;
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x5a);
    Maybe_MEMSET_180512a50((char*)auStack364128, 0xaa, 0x4e938);
    lVar6 = -0x2d0;
    do {
        *(longlong*)(auStack364128 + lVar6 + 0x2d0) =
            *(longlong*)(pbVar24 + lVar6 + 0x538) * 0x5a2a400557f7b751 + -0x2acdf4e74d39294d;
        *(longlong*)(auStack364128 + lVar6 + 0x5a8) =
            *(longlong*)(pbVar24 + lVar6 + 0x808) * 0x3e4a40d0461d0cf1 + 0x45ba6e53860af99d;
        *(longlong*)(auStack364128 + lVar6 + 0x878) =
            *(longlong*)(pbVar24 + lVar6 + 0xad8) * -0x4caa81fb6817f631 + -0x6bda09eec6680b92;
        lVar6 = lVar6 + 8;
    } while (lVar6 != 0);
    *(ulonglong*)(&auStack364128[720]) = *(longlong*)(pbVar24 + 0xf20) * 0x21e8ea0961709699 + -0x5d435df090e5c0d1;
    lVar6 = 0;

    do {
        lVar12 = 0;
        do {
            uVar15 = (ulonglong)((uint)lVar12 & 7);
            pbVar24 = p1_holder + lVar6 * 0x168;
            uVar8 = (ulonglong)
                ((*(int*)(pbVar24 + lVar12 * 4 + 0x3948) *
                    *(int*)((longlong)DAT_180920030 + uVar15 * 4) +
                    *(int*)((longlong)DAT_180920050 + uVar15 * 4)) * 0x3d1a194b + 0x4a39a5ef);
            uVar19 = uVar8 * 0x54f1676ee7325fa5 + 0x278477725ac5d9b9;
            iVar22 = 8;
            do {
                uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_180920070 + (ulonglong)((uint)uVar19 & 0xf) * 8)
                    ;
                iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
            alStack361960[lVar6 * 0x5a + lVar12] =
                uVar19 * -0x641c2e8f00000000 + uVar8 * 0xe0ddd831c5f132b + -0x2afaf8438c17a376;
            uVar19 = (ulonglong)
                ((*(int*)(pbVar24 + lVar12 * 4 + 0xd560) *
                    *(int*)((longlong)DAT_1809200f0 + uVar15 * 4) +
                    *(int*)((longlong)DAT_180920110 + uVar15 * 4)) * 0x4f1bd82d + 0x3bc18c80);
            uVar8 = uVar19 * 0x2c7a7c3fe99f3ac9 + 0x528e3665e49b6598;
            iVar22 = 8;
            do {
                uVar8 = (uVar8 >> 4) + *(longlong*)(DAT_180920130 + (ulonglong)((uint)uVar8 & 0xf) * 8);
                iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
            alStack282040[lVar6 * 0x5a + lVar12] =
                uVar8 * -0x272d735f00000000 + uVar19 * -0x141e3f26d22be469 + -0x51436375f4c4b485;
            uVar8 = (ulonglong)
                ((*(int*)(pbVar24 + lVar12 * 4 + 0x17178) * //offset too large... 
                    *(int*)((longlong)DAT_1809201b0 + uVar15 * 4) +
                    *(int*)((longlong)DAT_1809201d0 + uVar15 * 4)) * 0x78fd9c3 + 0xfc5cad86);
            uVar19 = uVar8 * -0x1f231342d7ee299f + 0x5e413b658e77dd13;
            iVar22 = 8;
            do {
                uVar19 = (uVar19 >> 4) + *(longlong*)(DAT_1809201f0 + (ulonglong)((uint)uVar19 & 0xf) * 8)
                    ;
                iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
            alStack202120[lVar6 * 0x5a + lVar12] =
                uVar19 * 0x3c3927f500000000 + uVar8 * 0x2f59d33577ac0e2b + -0x1c3ec4f78521b616;
            uVar19 = (ulonglong)
                ((*(int*)(pbVar24 + lVar12 * 4 + 0x20d90) *
                    *(int*)((longlong)DAT_180920270 + uVar15 * 4) +
                    *(int*)((longlong)DAT_180920290 + uVar15 * 4)) * 0x5b702a1b + 0xd0c226be);
            uVar15 = uVar19 * 0xb805ec5a1edb5f7 + 0xf39016fd97e5d670;
            iVar22 = 8;
            do {
                uVar15 = (uVar15 >> 4) + *(longlong*)(DAT_1809202b0 + (ulonglong)((uint)uVar15 & 0xf) * 8)
                    ;
                iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
            alStack122200[lVar6 * 0x5a + lVar12] =
                uVar15 * 0x10ec671d00000000 + uVar19 * 0x319371fdd4280205 + 0xe78775d750b7d0b;
            lVar12 = lVar12 + 1;
        } while (lVar12 != 0x5a);
        lVar6 = lVar6 + 1;
    } while (lVar6 != 0x6f);
    Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x8000);
 // Init tbles here?
    uVar33 = *(ulonglong*)(&local_87d0[264]);
    lVar6 = *(longlong*)(&local_87d0[264]);
    pbVar24 = p1_holder;
    longlong* alStack362680 = (longlong*)(auStack364128+0x5a8);
    local_80b0[394] = alStack362680[0];
    local_80b0[175] = alStack362680[1];
    local_80b0[91] = alStack362680[10];
    local_80b0[960] = alStack362680[11];
    local_80b0[1623] = alStack362680[12];
    local_80b0[727] = alStack362680[13];
    local_80b0[787] = alStack362680[14];
    local_80b0[206] = alStack362680[15];
    local_80b0[334] = alStack362680[16];
    local_80b0[869] = alStack362680[17];
    local_80b0[1335] = alStack362680[18];
    local_80b0[2131] = alStack362680[19];
    local_80b0[1392] = alStack362680[2];
    local_80b0[662] = alStack362680[20];
    local_80b0[1916] = alStack362680[21];
    local_80b0[1415] = alStack362680[22];
    local_80b0[36] = alStack362680[23];
    local_80b0[805] = alStack362680[24];
    local_80b0[946] = alStack362680[25];
    local_80b0[756] = alStack362680[26];
    local_80b0[1838] = alStack362680[27];
    local_80b0[1175] = alStack362680[28];
    local_80b0[665] = alStack362680[29];
    local_80b0[1218] = alStack362680[3];
    local_80b0[1204] = alStack362680[30];
    local_80b0[1429] = alStack362680[31];
    local_80b0[1593] = alStack362680[32];
    local_80b0[634] = alStack362680[33];
    local_80b0[818] = alStack362680[34];
    local_80b0[447] = alStack362680[35];
    local_80b0[164] = alStack362680[36];
    local_80b0[1505] = alStack362680[37];
    local_80b0[1065] = alStack362680[38];
    local_80b0[320] = alStack362680[39];
    local_80b0[1400] = alStack362680[4];
    local_80b0[488] = alStack362680[40];
    local_80b0[1119] = alStack362680[41];
    local_80b0[1316] = alStack362680[42];
    local_80b0[1073] = alStack362680[43];
    local_80b0[1139] = alStack362680[44];
    local_80b0[1581] = alStack362680[45];
    local_80b0[1376] = alStack362680[46];
    local_80b0[1194] = alStack362680[47];
    local_80b0[1609] = alStack362680[48];
    local_80b0[887] = alStack362680[49];
    local_80b0[1367] = alStack362680[5];
    local_80b0[1118] = alStack362680[50];
    local_80b0[847] = alStack362680[51];
    local_80b0[1965] = alStack362680[52];
    local_80b0[421] = alStack362680[53];
    local_80b0[593] = alStack362680[54];
    local_80b0[969] = alStack362680[55];
    local_80b0[456] = alStack362680[56];
    local_80b0[1927] = alStack362680[57];
    local_80b0[510] = alStack362680[58];
    local_80b0[1537] = alStack362680[59];
    local_80b0[1625] = alStack362680[6];
    local_80b0[1202] = alStack362680[60];
    local_80b0[1198] = alStack362680[61];
    local_80b0[1407] = alStack362680[62];
    local_80b0[894] = alStack362680[63];
    local_80b0[1855] = alStack362680[64];
    local_80b0[245] = alStack362680[65];
    local_80b0[1351] = alStack362680[66];
    local_80b0[3] = alStack362680[67];
    local_80b0[1152] = alStack362680[68];
    local_80b0[829] = alStack362680[69];
    local_80b0[1103] = alStack362680[7];
    local_80b0[1519] = alStack362680[70];
    local_80b0[171] = alStack362680[71];
    local_80b0[1985] = alStack362680[72];
    local_80b0[1560] = alStack362680[73];
    local_80b0[849] = alStack362680[74];
    local_80b0[395] = alStack362680[75];
    local_80b0[1928] = alStack362680[76];
    local_80b0[1126] = alStack362680[77];
    local_80b0[1828] = alStack362680[78];
    local_80b0[539] = alStack362680[79];
    local_80b0[1601] = alStack362680[8];
    local_80b0[1120] = alStack362680[80];
    local_80b0[1263] = alStack362680[81];
    local_80b0[373] = alStack362680[82];
    local_80b0[1201] = alStack362680[83];
    local_80b0[376] = alStack362680[84];
    local_80b0[1338] = alStack362680[85];
    local_80b0[1064] = alStack362680[86];
    local_80b0[936] = alStack362680[87];
    local_80b0[776] = alStack362680[88];
    local_80b0[631] = alStack362680[89];
    local_80b0[625] = alStack362680[9];
    local_80b0[1829] = *(longlong*)(&auStack364128[728]);
    local_80b0[1807] = *(longlong*)(&auStack364128[736]);
    local_80b0[932] = *(longlong*)(&auStack364128[808]);
    local_80b0[1765] = *(longlong*)(&auStack364128[816]);
    local_80b0[945] = *(longlong*)(&auStack364128[824]);
    local_80b0[1149] = *(longlong*)(&auStack364128[832]);
    local_80b0[1082] = *(longlong*)(&auStack364128[840]);
    local_80b0[500] = *(longlong*)(&auStack364128[848]);
    local_80b0[329] = *(longlong*)(&auStack364128[856]);
    local_80b0[1521] = *(longlong*)(&auStack364128[864]);
    local_80b0[766] = *(longlong*)(&auStack364128[872]);
    local_80b0[693] = *(longlong*)(&auStack364128[880]);
    local_80b0[148] = *(longlong*)(&auStack364128[744]);
    local_80b0[1504] = *(longlong*)(&auStack364128[888]);
    local_80b0[1806] = *(longlong*)(&auStack364128[896]);
    local_80b0[296] = *(longlong*)(&auStack364128[904]);
    local_80b0[1987] = *(longlong*)(&auStack364128[912]);
    local_80b0[152] = *(longlong*)(&auStack364128[920]);
    local_80b0[1434] = *(longlong*)(&auStack364128[928]);
    local_80b0[749] = *(longlong*)(&auStack364128[936]);
    local_80b0[486] = *(longlong*)(&auStack364128[944]);
    local_80b0[698] = *(longlong*)(&auStack364128[952]);
    local_80b0[1440] = *(longlong*)(&auStack364128[960]);
    local_80b0[1969] = *(longlong*)(&auStack364128[752]);
    local_80b0[1185] = *(longlong*)(&auStack364128[968]);
    local_80b0[372] = *(longlong*)(&auStack364128[976]);
    local_80b0[957] = *(longlong*)(&auStack364128[984]);
    local_80b0[63] = *(longlong*)(&auStack364128[992]);
    local_80b0[1502] = *(longlong*)(&auStack364128[1000]);
    local_80b0[297] = *(longlong*)(&auStack364128[1008]);
    local_80b0[910] = *(longlong*)(&auStack364128[1016]);
    local_80b0[920] = *(longlong*)(&auStack364128[1024]);
    local_80b0[27] = *(longlong*)(&auStack364128[1032]);
    local_80b0[1778] = *(longlong*)(&auStack364128[1040]);
    local_80b0[1856] = *(longlong*)(&auStack364128[760]);
    local_80b0[2086] = *(longlong*)(&auStack364128[1048]);
    local_80b0[471] = *(longlong*)(&auStack364128[1056]);
    local_80b0[1616] = *(longlong*)(&auStack364128[1064]);
    local_80b0[544] = *(longlong*)(&auStack364128[1072]);
    local_80b0[1673] = *(longlong*)(&auStack364128[1080]);
    local_80b0[2106] = *(longlong*)(&auStack364128[1088]);
    local_80b0[1130] = *(longlong*)(&auStack364128[1096]);
    local_80b0[1735] = *(longlong*)(&auStack364128[1104]);
    local_80b0[1393] = *(longlong*)(&auStack364128[1112]);
    local_80b0[1195] = *(longlong*)(&auStack364128[1120]);
    local_80b0[795] = *(longlong*)(&auStack364128[768]);
    local_80b0[1895] = *(longlong*)(&auStack364128[1128]);
    local_80b0[215] = *(longlong*)(&auStack364128[1136]);
    local_80b0[933] = *(longlong*)(&auStack364128[1144]);
    local_80b0[191] = *(longlong*)(&auStack364128[1152]);
    local_80b0[9] = *(longlong*)(&auStack364128[1160]);
    local_80b0[1619] = *(longlong*)(&auStack364128[1168]);
    local_80b0[1716] = *(longlong*)(&auStack364128[1176]);
    local_80b0[2021] = *(longlong*)(&auStack364128[1184]);
    local_80b0[1635] = *(longlong*)(&auStack364128[1192]);
    local_80b0[2024] = *(longlong*)(&auStack364128[1200]);
    local_80b0[965] = *(longlong*)(&auStack364128[776]);
    local_80b0[956] = *(longlong*)(&auStack364128[1208]);
    local_80b0[1740] = *(longlong*)(&auStack364128[1216]);
    local_80b0[571] = *(longlong*)(&auStack364128[1224]);
    local_80b0[1514] = *(longlong*)(&auStack364128[1232]);
    local_80b0[1095] = *(longlong*)(&auStack364128[1240]);
    local_80b0[244] = *(longlong*)(&auStack364128[1248]);
    local_80b0[392] = *(longlong*)(&auStack364128[1256]);
    local_80b0[22] = *(longlong*)(&auStack364128[1264]);
    local_80b0[2049] = *(longlong*)(&auStack364128[1272]);
    local_80b0[954] = *(longlong*)(&auStack364128[1280]);
    local_80b0[371] = *(longlong*)(&auStack364128[784]);
    local_80b0[794] = *(longlong*)(&auStack364128[1288]);
    local_80b0[811] = *(longlong*)(&auStack364128[1296]);
    local_80b0[1021] = *(longlong*)(&auStack364128[1304]);
    local_80b0[1047] = *(longlong*)(&auStack364128[1312]);
    local_80b0[1484] = *(longlong*)(&auStack364128[1320]);
    local_80b0[670] = *(longlong*)(&auStack364128[1328]);
    local_80b0[896] = *(longlong*)(&auStack364128[1336]);
    local_80b0[246] = *(longlong*)(&auStack364128[1344]);
    local_80b0[140] = *(longlong*)(&auStack364128[1352]);
    local_80b0[569] = *(longlong*)(&auStack364128[1360]);
    local_80b0[537] = *(longlong*)(&auStack364128[792]);
    local_80b0[743] = *(longlong*)(&auStack364128[1368]);
    local_80b0[955] = *(longlong*)(&auStack364128[1376]);
    local_80b0[1403] = *(longlong*)(&auStack364128[1384]);
    local_80b0[972] = *(longlong*)(&auStack364128[1392]);
    local_80b0[337] = *(longlong*)(&auStack364128[1400]);
    local_80b0[464] = *(longlong*)(&auStack364128[1408]);
    local_80b0[1219] = *(longlong*)(&auStack364128[1416]);
    local_80b0[1692] = *(longlong*)(&auStack364128[1424]);
    local_80b0[1329] = *(longlong*)(&auStack364128[1432]);
    local_80b0[1290] = *(longlong*)(&auStack364128[1440]);
    local_80b0[381] = *(longlong*)(&auStack364128[800]);
    local_80b0[1915] = *(longlong*)(&auStack364128[0]);
    local_80b0[923] = *(longlong*)(&auStack364128[8]);
    local_80b0[2059] = *(longlong*)(&auStack364128[80]);
    local_80b0[659] = *(longlong*)(&auStack364128[88]);
    local_80b0[1536] = *(longlong*)(&auStack364128[96]);
    local_80b0[1904] = *(longlong*)(&auStack364128[104]);
    local_80b0[1766] = *(longlong*)(&auStack364128[112]);
    local_80b0[1963] = *(longlong*)(&auStack364128[120]);
    local_80b0[1259] = *(longlong*)(&auStack364128[128]);
    local_80b0[1256] = *(longlong*)(&auStack364128[136]);
    local_80b0[4] = *(longlong*)(&auStack364128[144]);
    local_80b0[291] = *(longlong*)(&auStack364128[152]);
    local_80b0[1621] = *(longlong*)(&auStack364128[16]); 
    local_80b0[375] = *(longlong*)(&auStack364128[160]);
    local_80b0[813] = *(longlong*)(&auStack364128[168]);
    local_80b0[142] = *(longlong*)(&auStack364128[176]);
    local_80b0[87] = *(longlong*)(&auStack364128[184]);
    local_80b0[1853] = *(longlong*)(&auStack364128[192]);
    local_80b0[470] = *(longlong*)(&auStack364128[200]);
    local_80b0[2008] = *(longlong*)(&auStack364128[208]);
    local_80b0[1337] = *(longlong*)(&auStack364128[216]);
    local_80b0[1196] = *(longlong*)(&auStack364128[224]);
    local_80b0[2110] = *(longlong*)(&auStack364128[232]);
    local_80b0[1713] = *(longlong*)(&auStack364128[24]);
    local_80b0[59] = *(longlong*)(&auStack364128[240]);
    local_80b0[24] = *(longlong*)(&auStack364128[248]);
    local_80b0[112] = *(longlong*)(&auStack364128[256]);
    local_80b0[34] = *(longlong*)(&auStack364128[264]);
    local_80b0[202] = *(longlong*)(&auStack364128[272]);
    local_80b0[778] = *(longlong*)(&auStack364128[280]);
    local_80b0[1043] = *(longlong*)(&auStack364128[288]);
    local_80b0[50] = *(longlong*)(&auStack364128[296]);
    local_80b0[629] = *(longlong*)(&auStack364128[304]);
    local_80b0[1758] = *(longlong*)(&auStack364128[312]);
    local_80b0[1262] = *(longlong*)(&auStack364128[32]);
    local_80b0[1555] = *(longlong*)(&auStack364128[320]);
    local_80b0[2124] = *(longlong*)(&auStack364128[328]);
    local_80b0[183] = *(longlong*)(&auStack364128[336]);
    local_80b0[1123] = *(longlong*)(&auStack364128[344]);
    local_80b0[466] = *(longlong*)(&auStack364128[352]);
    local_80b0[293] = *(longlong*)(&auStack364128[360]);
    local_80b0[2019] = *(longlong*)(&auStack364128[368]);
    local_80b0[428] = *(longlong*)(&auStack364128[376]);
    local_80b0[113] = *(longlong*)(&auStack364128[384]);
    local_80b0[2120] = *(longlong*)(&auStack364128[392]);
    local_80b0[209] = *(longlong*)(&auStack364128[40]);
    local_80b0[346] = *(longlong*)(&auStack364128[400]);
    local_80b0[2122] = *(longlong*)(&auStack364128[408]);
    local_80b0[1978] = *(longlong*)(&auStack364128[416]);
    local_80b0[1658] = *(longlong*)(&auStack364128[424]);
    local_80b0[1558] = *(longlong*)(&auStack364128[432]);
    local_80b0[1452] = *(longlong*)(&auStack364128[440]);
    local_80b0[1960] = *(longlong*)(&auStack364128[448]);
    local_80b0[1348] = *(longlong*)(&auStack364128[456]);
    local_80b0[966] = *(longlong*)(&auStack364128[464]);
    local_80b0[55] = *(longlong*)(&auStack364128[472]);
    local_80b0[1480] = *(longlong*)(&auStack364128[48]);
    local_80b0[947] = *(longlong*)(&auStack364128[480]);
    local_80b0[11] = *(longlong*)(&auStack364128[488]);
    local_80b0[1386] = *(longlong*)(&auStack364128[496]);
    local_80b0[1019] = *(longlong*)(&auStack364128[504]);
    local_80b0[78] = *(longlong*)(&auStack364128[512]);
    local_80b0[568] = *(longlong*)(&auStack364128[520]);
    local_80b0[1957] = *(longlong*)(&auStack364128[528]);
    local_80b0[503] = *(longlong*)(&auStack364128[536]);
    local_80b0[146] = *(longlong*)(&auStack364128[544]);
    local_80b0[1054] = *(longlong*)(&auStack364128[552]);
    local_80b0[121] = *(longlong*)(&auStack364128[56]);
    local_80b0[836] = *(longlong*)(&auStack364128[560]);
    local_80b0[1981] = *(longlong*)(&auStack364128[568]);
    local_80b0[678] = *(longlong*)(&auStack364128[576]);
    local_80b0[2104] = *(longlong*)(&auStack364128[584]);
    local_80b0[769] = *(longlong*)(&auStack364128[592]);
    local_80b0[680] = *(longlong*)(&auStack364128[600]);
    local_80b0[1353] = *(longlong*)(&auStack364128[608]);
    local_80b0[1309] = *(longlong*)(&auStack364128[616]);
    local_80b0[1181] = *(longlong*)(&auStack364128[624]);
    local_80b0[469] = *(longlong*)(&auStack364128[632]);
    local_80b0[443] = *(longlong*)(&auStack364128[64]);
    local_80b0[1886] = *(longlong*)(&auStack364128[640]);
    local_80b0[370] = *(longlong*)(&auStack364128[648]);
    local_80b0[1883] = *(longlong*)(&auStack364128[656]);
    local_80b0[1678] = *(longlong*)(&auStack364128[664]);
    local_80b0[318] = *(longlong*)(&auStack364128[672]);
    local_80b0[806] = *(longlong*)(&auStack364128[680]);
    local_80b0[1820] = *(longlong*)(&auStack364128[688]);
    local_80b0[2078] = *(longlong*)(&auStack364128[696]);
    local_80b0[603] = *(longlong*)(&auStack364128[704]);
    local_80b0[1591] = *(longlong*)(&auStack364128[712]);
    local_80b0[1066] = *(longlong*)(&auStack364128[72]);
    local_80b0[1306] = *(longlong*)(&auStack364128[720]);
    local_80b0[277] = *(longlong*)(&local_8f90[0]); 
    local_80b0[26] = *(longlong*)(&local_8f90[8]);
    local_80b0[2085] = *(longlong*)(&local_8f90[80]);
    local_80b0[1029] = *(longlong*)(&local_8f90[88]);
    local_80b0[1675] = *(longlong*)(&local_8f90[96]);
    local_80b0[781] = *(longlong*)(&local_8f90[104]);
    local_80b0[1445] = *(longlong*)(&local_8f90[112]);
    local_80b0[1471] = *(longlong*)(&local_8f90[120]);
    local_80b0[238] = *(longlong*)(&local_8f90[128]);
    local_80b0[527] = *(longlong*)(&local_8f90[136]);
    local_80b0[1749] = *(longlong*)(&local_8f90[144]);
    local_80b0[1200] = *(longlong*)(&local_8f90[152]);
    local_80b0[21] = *(longlong*)(&local_8f90[16]);
    local_80b0[1269] = *(longlong*)(&local_8f90[160]);
    local_80b0[95] = *(longlong*)(&local_8f90[168]);
    local_80b0[918] = *(longlong*)(&local_8f90[176]);
    local_80b0[358] = *(longlong*)(&local_8f90[184]);
    local_80b0[1636] = *(longlong*)(&local_8f90[192]);
    local_80b0[1893] = *(longlong*)(&local_8f90[200]);
    local_80b0[104] = *(longlong*)(&local_8f90[208]);
    local_80b0[1933] = *(longlong*)(&local_8f90[216]);
    local_80b0[1669] = *(longlong*)(&local_8f90[224]);
    local_80b0[2042] = *(longlong*)(&local_8f90[232]);
    local_80b0[1582] = *(longlong*)(&local_8f90[24]);
    local_80b0[618] = *(longlong*)(&local_8f90[240]);
    local_80b0[2073] = *(longlong*)(&local_8f90[248]);
    local_80b0[1509] = *(longlong*)(&local_8f90[256]);
    local_80b0[550] = *(longlong*)(&local_8f90[264]);
    local_80b0[948] = *(longlong*)(&local_8f90[272]);
    local_80b0[1662] = *(longlong*)(&local_8f90[280]);
    local_80b0[584] = *(longlong*)(&local_8f90[288]);
    local_80b0[2068] = *(longlong*)(&local_8f90[296]);
    local_80b0[449] = *(longlong*)(&local_8f90[304]);
    local_80b0[485] = *(longlong*)(&local_8f90[312]);
    local_80b0[1311] = *(longlong*)(&local_8f90[32]);
    local_80b0[521] = *(longlong*)(&local_8f90[320]);
    local_80b0[1421] = *(longlong*)(&local_8f90[328]);
    local_80b0[861] = *(longlong*)(&local_8f90[336]);
    local_80b0[57] = *(longlong*)(&local_8f90[344]);
    local_80b0[212] = *(longlong*)(&local_8f90[352]);
    local_80b0[1542] = *(longlong*)(&local_8f90[360]);
    local_80b0[2089] = *(longlong*)(&local_8f90[368]);
    local_80b0[1326] = *(longlong*)(&local_8f90[376]);
    local_80b0[1613] = *(longlong*)(&local_8f90[384]);
    local_80b0[1681] = *(longlong*)(&local_8f90[392]);
    local_80b0[720] = *(longlong*)(&local_8f90[40]);
    local_80b0[978] = *(longlong*)(&local_8f90[400]);
    local_80b0[735] = *(longlong*)(&local_8f90[408]);
    local_80b0[1493] = *(longlong*)(&local_8f90[416]);
    local_80b0[1936] = *(longlong*)(&local_8f90[424]);
    local_80b0[718] = *(longlong*)(&local_8f90[432]);
    local_80b0[1374] = *(longlong*)(&local_8f90[440]);
    local_80b0[1962] = *(longlong*)(&local_8f90[448]);
    local_80b0[1628] = *(longlong*)(&local_8f90[456]);
    local_80b0[1513] = *(longlong*)(&local_8f90[464]);
    local_80b0[407] = *(longlong*)(&local_8f90[472]);
    local_80b0[123] = *(longlong*)(&local_8f90[48]);
    local_80b0[1496] = *(longlong*)(&local_8f90[480]);
    local_80b0[2038] = *(longlong*)(&local_8f90[488]);
    local_80b0[685] = *(longlong*)(&local_8f90[496]);
    local_80b0[1485] = *(longlong*)(&local_8f90[504]);
    local_80b0[750] = *(longlong*)(&local_8f90[512]);
    local_80b0[1062] = *(longlong*)(&local_8f90[520]);
    local_80b0[77] = *(longlong*)(&local_8f90[528]);
    local_80b0[1767] = *(longlong*)(&local_8f90[536]);
    local_80b0[90] = *(longlong*)(&local_8f90[544]);
    local_80b0[1443] = *(longlong*)(&local_8f90[552]);
    local_80b0[677] = *(longlong*)(&local_8f90[56]);
    local_80b0[39] = *(longlong*)(&local_8f90[560]);
    local_80b0[1762] = *(longlong*)(&local_8f90[568]);
    local_80b0[1398] = *(longlong*)(&local_8f90[576]);
    local_80b0[1525] = *(longlong*)(&local_8f90[584]);
    local_80b0[808] = *(longlong*)(&local_8f90[592]);
    local_80b0[115] = *(longlong*)(&local_8f90[600]);
    local_80b0[1955] = *(longlong*)(&local_8f90[608]);
    local_80b0[710] = *(longlong*)(&local_8f90[616]);
    local_80b0[1394] = *(longlong*)(&local_8f90[624]);
    local_80b0[72] = *(longlong*)(&local_8f90[632]);
    local_80b0[2032] = *(longlong*)(&local_8f90[64]);
    local_80b0[2064] = *(longlong*)(&local_8f90[640]);
    local_80b0[1606] = *(longlong*)(&local_8f90[648]);
    local_80b0[343] = *(longlong*)(&local_8f90[656]);
    local_80b0[313] = *(longlong*)(&local_8f90[664]);
    local_80b0[1044] = *(longlong*)(&local_8f90[672]);
    local_80b0[976] = *(longlong*)(&local_8f90[680]);
    local_80b0[590] = *(longlong*)(&local_8f90[688]);
    local_80b0[1550] = *(longlong*)(&local_8f90[696]);
    local_80b0[1296] = *(longlong*)(&local_8f90[704]);
    local_80b0[331] = *(longlong*)(&local_8f90[712]);
    local_80b0[1257] = *(longlong*)(&local_8f90[72]);
    local_80b0[195] = *(longlong*)((longlong)local_87d0+0);
    local_80b0[86] = *(longlong*)((longlong)local_87d0 + 8);
    local_80b0[2] = *(longlong*)((longlong)local_87d0 + 80);
    local_80b0[18] = *(longlong*)((longlong)local_87d0 + 88);
    local_80b0[186] = *(longlong*)((longlong)local_87d0 + 96);
    local_80b0[143] = *(longlong*)((longlong)local_87d0 + 104);
    local_80b0[257] = *(longlong*)((longlong)local_87d0 + 112);
    local_80b0[185] = *(longlong*)((longlong)local_87d0 + 120);
    local_80b0[418] = *(longlong*)((longlong)local_87d0 + 128);
    local_80b0[120] = *(longlong*)((longlong)local_87d0 + 136);
    local_80b0[44] = *(longlong*)((longlong)local_87d0 + 144);
    local_80b0[14] = *(longlong*)((longlong)local_87d0 + 152);
    local_80b0[126] = *(longlong*)((longlong)local_87d0 + 16);
    local_80b0[249] = *(longlong*)((longlong)local_87d0 + 160);
    local_80b0[218] = *(longlong*)((longlong)local_87d0 + 168);
    local_80b0[728] = *(longlong*)((longlong)local_87d0 + 176);
    local_80b0[68] = *(longlong*)((longlong)local_87d0 + 184);
    local_80b0[429] = *(longlong*)((longlong)local_87d0 + 192);
    local_80b0[145] = *(longlong*)((longlong)local_87d0 + 200);
    local_80b0[452] = *(longlong*)((longlong)local_87d0 + 208);
    local_80b0[255] = *(longlong*)((longlong)local_87d0 + 216);
    local_80b0[448] = *(longlong*)((longlong)local_87d0 + 224);
    local_80b0[103] = *(longlong*)((longlong)local_87d0 + 232);
    local_80b0[221] = *(longlong*)((longlong)local_87d0 + 24);
    local_80b0[540] = *(longlong*)((longlong)local_87d0 + 240);
    local_80b0[431] = *(longlong*)((longlong)local_87d0 + 248);
    local_80b0[512] = *(longlong*)((longlong)local_87d0 + 256);
    local_80b0[66] = *(longlong*)((longlong)local_87d0 + 264);
    local_80b0[855] = *(longlong*)((longlong)local_87d0 + 272);
    local_80b0[284] = *(longlong*)((longlong)local_87d0 + 280);
    local_80b0[348] = *(longlong*)((longlong)local_87d0 + 288);
    local_80b0[364] = *(longlong*)((longlong)local_87d0 + 296);
    local_80b0[508] = *(longlong*)((longlong)local_87d0 + 304);
    local_80b0[837] = *(longlong*)((longlong)local_87d0 + 312);
    local_80b0[233] = *(longlong*)((longlong)local_87d0 + 32);
    local_80b0[458] = *(longlong*)((longlong)local_87d0 + 320);
    local_80b0[65] = *(longlong*)((longlong)local_87d0 + 328);
    local_80b0[620] = *(longlong*)((longlong)local_87d0 + 336);
    local_80b0[908] = *(longlong*)((longlong)local_87d0 + 344);
    local_80b0[465] = *(longlong*)((longlong)local_87d0 + 352);
    local_80b0[1685] = *(longlong*)((longlong)local_87d0 + 360);
    local_80b0[1134] = *(longlong*)((longlong)local_87d0 + 368);
    local_80b0[1315] = *(longlong*)((longlong)local_87d0 + 376);
    local_80b0[1322] = *(longlong*)((longlong)local_87d0 + 384);
    local_80b0[1270] = *(longlong*)((longlong)local_87d0 + 392);
    local_80b0[187] = *(longlong*)((longlong)local_87d0 + 40);
    local_80b0[2118] = *(longlong*)((longlong)local_87d0 + 400);
    local_80b0[509] = *(longlong*)((longlong)local_87d0 + 408);
    local_80b0[1124] = *(longlong*)((longlong)local_87d0 + 416);
    local_80b0[1234] = *(longlong*)((longlong)local_87d0 + 424);
    local_80b0[1188] = *(longlong*)((longlong)local_87d0 + 432);
    local_80b0[884] = *(longlong*)((longlong)local_87d0 + 440);
    local_80b0[489] = *(longlong*)((longlong)local_87d0 + 448);
    local_80b0[380] = *(longlong*)((longlong)local_87d0 + 456);
    local_80b0[636] = *(longlong*)((longlong)local_87d0 + 464);
    local_80b0[1503] = *(longlong*)((longlong)local_87d0 + 472);
    local_80b0[181] = *(longlong*)((longlong)local_87d0 + 48);
    local_80b0[367] = *(longlong*)((longlong)local_87d0 + 480);
    local_80b0[1099] = *(longlong*)((longlong)local_87d0 + 488);
    local_80b0[1551] = *(longlong*)((longlong)local_87d0 + 496);
    local_80b0[106] = *(longlong*)((longlong)local_87d0 + 504);
    local_80b0[542] = *(longlong*)((longlong)local_87d0 + 512);
    local_80b0[1717] = *(longlong*)((longlong)local_87d0 + 520);
    local_80b0[731] = *(longlong*)((longlong)local_87d0 + 528);
    local_80b0[1535] = *(longlong*)((longlong)local_87d0 + 536);
    local_80b0[745] = *(longlong*)((longlong)local_87d0 + 544);
    local_80b0[1469] = *(longlong*)((longlong)local_87d0 + 552);
    local_80b0[138] = *(longlong*)((longlong)local_87d0 + 56);
    local_80b0[2025] = *(longlong*)((longlong)local_87d0 + 560);
    local_80b0[1660] = *(longlong*)((longlong)local_87d0 + 568);
    local_80b0[1481] = *(longlong*)((longlong)local_87d0 + 576);
    local_80b0[1664] = *(longlong*)((longlong)local_87d0 + 584);
    local_80b0[20] = *(longlong*)((longlong)local_87d0 + 592);
    local_80b0[700] = *(longlong*)((longlong)local_87d0 + 600);
    local_80b0[1360] = *(longlong*)((longlong)local_87d0 + 608);
    local_80b0[1552] = *(longlong*)((longlong)local_87d0 + 616);
    local_80b0[875] = *(longlong*)((longlong)local_87d0 + 624);
    local_80b0[1128] = *(longlong*)((longlong)local_87d0 + 632);
    local_80b0[48] = *(longlong*)((longlong)local_87d0 + 64);
    local_80b0[1642] = *(longlong*)((longlong)local_87d0 + 640);
    local_80b0[1409] = *(longlong*)((longlong)local_87d0 + 648);
    local_80b0[1774] = *(longlong*)((longlong)local_87d0 + 656);
    local_80b0[648] = *(longlong*)((longlong)local_87d0 + 664);
    local_80b0[817] = *(longlong*)((longlong)local_87d0 + 672);
    local_80b0[1060] = *(longlong*)((longlong)local_87d0 + 680);
    local_80b0[730] = *(longlong*)((longlong)local_87d0 + 688);
    local_80b0[1967] = *(longlong*)((longlong)local_87d0 + 696);
    local_80b0[2114] = *(longlong*)((longlong)local_87d0 + 704);
    local_80b0[1242] = *(longlong*)((longlong)local_87d0 + 712);
    local_80b0[243] = *(longlong*)((longlong)local_87d0 + 72);


    uVar45 = 1;
    bVar28 = false;
    uVar25 = 0;
    iVar22 = 0;
    uVar27 = 0;
    do {
        lVar12 = (longlong)iVar22 * 0x10;
        if (false) goto LAB_18017a47b;
        uVar26 = (ushort)uVar27;
        switch ((DAT_18136f790)[lVar12]) {  
        case 0:
            uVar15 = (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+14);
            local_80b0[*(ushort*)(lVar12 + DAT_18136f790+12) ^ uVar26] =
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26] *
                *(longlong*)(DAT_180920cc0 + uVar15 * 8+8) +
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] *
                *(longlong*)(DAT_180920cc0 + uVar15 * 8) + *(longlong*)(DAT_180920cc0 +0x10+ uVar15 * 8);
            goto LAB_18017a479;
        case 1:
            uVar1 = *(ushort*)(lVar12 + DAT_18136f790+2);
            lVar20 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26];
            goto LAB_18017a130;
        case 2:
            lVar20 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26] *
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26];
            uVar1 = *(ushort*)(lVar12 + DAT_18136f790+6);
        LAB_18017a130:
            lVar20 = lVar20 + local_80b0[uVar1 ^ uVar26];
            goto LAB_18017a370;
        case 3:
            uVar15 = (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+14);
            lVar20 = (local_80b0[*(ushort*)(lVar12 + DAT_18136f790+8) ^ uVar26] -
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+10) ^ uVar26]) *
                *(longlong*)(DAT_180920cc0 +0x10+ uVar15 * 8) +
                (local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26] -
                    local_80b0[*(ushort*)(lVar12 + DAT_18136f790+6) ^ uVar26]) *
                *(longlong*)(DAT_180920cc0+8 + uVar15 * 8) +
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] *
                *(longlong*)(DAT_180920cc0 + uVar15 * 8) +
                *(longlong*)(DAT_180920cc0 +0x20 + uVar15 * 8) +
                (ulonglong) * (byte*)(lVar12 + DAT_18136f790+1) *
                *(longlong*)(DAT_180920cc0 +0x18+ uVar15 * 8);
            break;
        case 4:
            uVar19 = (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+14);
            uVar15 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] *
                *(longlong*)(DAT_180920cc0+0x80 + uVar19 * 8) +
                *(longlong*)(DAT_180920cc0 +0x88+ uVar19 * 8);
            cVar11 = *(char*)(lVar12 + DAT_18136f790+1);
            if (cVar11 != '\0') {
                do {
                    uVar15 = (uVar15 >> 4) * *(longlong*)(DAT_180920cc0 +0x90+ uVar19 * 8) +
                        *(longlong*)(DAT_180920cc0 + (((uint)uVar15 & 0xf) + uVar19) * 8);
                    cVar11 = cVar11 + -1;
                } while (cVar11 != '\0');
            }
            local_80b0[*(ushort*)(lVar12 + DAT_18136f790+12) ^ uVar26] =
                uVar15 * *(longlong*)(DAT_180920cc0 +0x98+ uVar19 * 8) +
                *(longlong*)(DAT_180920cc0 +0xa0+ uVar19 * 8);
            iVar22 = iVar22 + 1;
            goto LAB_18017a47b;
        case 5:
            uVar15 = (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+14);
            lVar20 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] *
                *(longlong*)(DAT_180920cc0+8 + uVar15 * 8) +
                *(longlong*)(DAT_180920cc0+0x18 + uVar15 * 8) +
                (*(longlong*)(DAT_180920cc0 + uVar15 * 8) *
                    local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] +
                    *(longlong*)(DAT_180920cc0+0x10 + uVar15 * 8)) *
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26];
            goto LAB_18017a370;
        case 6:
            uVar15 = (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+14);
            local_80b0[*(ushort*)(lVar12 + DAT_18136f790+12) ^ uVar26] =
                (*(longlong*)(DAT_180920cc0 + uVar15 * 8) *
                    local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] +
                    *(longlong*)(DAT_180920cc0 +0x10+ uVar15 * 8)) *
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26] +
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] *
                *(longlong*)(DAT_180920cc0+8 + uVar15 * 8) +
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+6) ^ uVar26] *
                *(longlong*)(DAT_180920cc0+0x18 + uVar15 * 8) + *(longlong*)(DAT_180920cc0+0x20 + uVar15 * 8);
            goto LAB_18017a479;
        case 7:
            lVar20 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26] -
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26];
            break;
        case 8:
            lVar20 = local_80b0[*(ushort*)(lVar12 + DAT_18136f790+4) ^ uVar26] *
                local_80b0[*(ushort*)(lVar12 + DAT_18136f790+2) ^ uVar26];
        LAB_18017a370:
            local_80b0[*(ushort*)(lVar12 + DAT_18136f790+12) ^ uVar26] = lVar20;
            goto LAB_18017a479;
        default:
            goto LAB_18017a47b;
        case 10:
            uVar45 = uVar45 * 0x77 & 0x7ff;
            uVar27 = uVar27 ^ uVar45;
            goto LAB_18017a479;
        case 0xb:
            uVar26 = *(ushort*)(lVar12 + DAT_18136f790+12);
            lVar12 = local_80b0[uVar26];
            local_80b0[uVar26] = local_80b0[uVar45 ^ uVar26];
            local_80b0[uVar45 ^ uVar26] = lVar12;
            goto LAB_18017a479;
        case 0xc:
            uVar25 = uVar25 + 1;
            bVar28 = uVar25 == 0x6f;
            iVar22 = 0;
            goto LAB_18017a47b;
        case 0xd:
            lVar20 = alStack361960
                [(ulonglong)uVar25 * 0x5a + (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+2)];
            break;
        case 0xe:
            lVar20 = alStack282040
                [(ulonglong)uVar25 * 0x5a + (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+2)];
            break;
        case 0xf:
            lVar20 = alStack202120
                [(ulonglong)uVar25 * 0x5a + (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+2)];
            break;
        case 0x10:
            lVar20 = alStack122200
                [(ulonglong)uVar25 * 0x5a + (ulonglong) * (ushort*)(lVar12 + DAT_18136f790+2)];
        }
        local_80b0[*(ushort*)(lVar12 + DAT_18136f790+12) ^ uVar26] = lVar20;
    LAB_18017a479:
        iVar22 = iVar22 + 1;
    LAB_18017a47b:
        if (bVar28) {
  
       
           * (longlong*)((longlong)local_87d0 + 0) = local_80b0[1730];
           *(longlong*)((longlong)local_87d0 + 8) = local_80b0[1623];
           *(longlong*)((longlong)local_87d0+80) = local_80b0[1539];
            *(ulonglong*)(&local_87d0[44]) = local_80b0[1555];
            *(longlong*)((longlong)local_87d0 + 96) = local_80b0[1723];
            *(ulonglong*)(&local_87d0[52]) = local_80b0[1678];
            *(longlong*)((longlong)local_87d0 + 112) = local_80b0[1792];
            *(longlong*)((longlong)local_87d0 + 120) = local_80b0[1720];
            *(ulonglong*)(&local_87d0[64]) = local_80b0[1955];
            *(longlong*)((longlong)local_87d0 + 136) = local_80b0[1657];
            *(longlong*)((longlong)local_87d0 + 144) = local_80b0[1581];
            *(ulonglong*)(&local_87d0[76]) = local_80b0[1551];
            *(longlong*)((longlong)local_87d0 + 16) =  local_80b0[1663];
            *(longlong*)((longlong)local_87d0 + 160) = local_80b0[1784];
            *(longlong*)((longlong)local_87d0 + 168) = local_80b0[1755];
            *(longlong*)((longlong)local_87d0 + 176) = local_80b0[1241];
            *(longlong*)((longlong)local_87d0 + 184) = local_80b0[1605];
            *(longlong*)((longlong)local_87d0 + 192) = local_80b0[1964];
            *(longlong*)((longlong)local_87d0 + 200) = local_80b0[1680];
            *(longlong*)((longlong)local_87d0 + 208) = local_80b0[1989];
            *(longlong*)((longlong)local_87d0 + 216) = local_80b0[1790];
            *(longlong*)((longlong)local_87d0 + 224) = local_80b0[1985];
            *(longlong*)((longlong)local_87d0 + 232) = local_80b0[1638];
            *(longlong*)((longlong)local_87d0 + 24) =  local_80b0[1756];
            *(longlong*)((longlong)local_87d0 + 240) = local_80b0[1053];
            *(longlong*)((longlong)local_87d0 + 248) = local_80b0[1966];
            *(longlong*)((longlong)local_87d0 + 256) = local_80b0[1025];
            *(longlong*)((longlong)local_87d0 + 264) = local_80b0[1603];
            *(longlong*)((longlong)local_87d0 + 272) = local_80b0[1366];
            *(longlong*)((longlong)local_87d0 + 280) = local_80b0[1821];
            *(longlong*)((longlong)local_87d0 + 288) = local_80b0[1885];
            *(longlong*)((longlong)local_87d0 + 296) = local_80b0[1901];
            *(longlong*)((longlong)local_87d0 + 304) = local_80b0[2045];
            *(ulonglong*)(&local_87d0[156]) = local_80b0[1348];
            *(longlong*)((longlong)local_87d0 + 32) =  local_80b0[1768];
            *(longlong*)((longlong)local_87d0 + 320) = local_80b0[1995];
            *(longlong*)((longlong)local_87d0 + 328) = local_80b0[1600];
            *(longlong*)((longlong)local_87d0 + 336) = local_80b0[1133];
            *(ulonglong*)(&local_87d0[172]) = local_80b0[1421];
            *(longlong*)((longlong)local_87d0 + 352) = local_80b0[2000];
            *(longlong*)((longlong)local_87d0 + 360) = local_80b0[148];
            *(longlong*)((longlong)local_87d0 + 368) = local_80b0[623];
            *(longlong*)((longlong)local_87d0 + 376) = local_80b0[802];
            *(ulonglong*)(&local_87d0[192]) = local_80b0[811];
            *(longlong*)((longlong)local_87d0 + 392) = local_80b0[759];
            *(longlong*)((longlong)local_87d0 + 40) =  local_80b0[1722];
            *(longlong*)((longlong)local_87d0 + 400) = local_80b0[3655];
            *(longlong*)((longlong)local_87d0 + 408) = local_80b0[2044];
            *(longlong*)((longlong)local_87d0 + 416) = local_80b0[613];
            *(longlong*)((longlong)local_87d0 + 424) = local_80b0[723];
            *(ulonglong*)(&local_87d0[216]) = local_80b0[677];
            *(longlong*)((longlong)local_87d0 + 440) = local_80b0[1397];
            *(ulonglong*)(&local_87d0[224]) = local_80b0[2024];
            *(longlong*)((longlong)local_87d0 + 456) = local_80b0[1917];
            *(ulonglong*)(&local_87d0[232]) = local_80b0[1149];
            *(longlong*)((longlong)local_87d0 + 472) = local_80b0[990];
            *(ulonglong*)(&local_87d0[24]) = local_80b0[1716];
            *(longlong*)((longlong)local_87d0 + 480) = local_80b0[1902];
            *(longlong*)((longlong)local_87d0 + 488) = local_80b0[586];
            *(longlong*)((longlong)local_87d0 + 496) = local_80b0[14];
            *(longlong*)((longlong)local_87d0 + 504) = local_80b0[1643];
            *(longlong*)((longlong)local_87d0 + 512) = local_80b0[1055];
            *(longlong*)((longlong)local_87d0 + 520) = local_80b0[180];
            *(longlong*)((longlong)local_87d0 + 528) = local_80b0[1242];
            *(longlong*)((longlong)local_87d0 + 536) = local_80b0[1022];
            *(ulonglong*)(&local_87d0[272]) = local_80b0[1256];
            *(ulonglong*)(&local_87d0[276]) = local_80b0[956];
            *(ulonglong*)(&local_87d0[28]) = local_80b0[1675];
            *(longlong*)((longlong)local_87d0 + 560) = local_80b0[488];
            *(longlong*)((longlong)local_87d0 + 568) = local_80b0[125];
            *(longlong*)((longlong)local_87d0 + 576) = local_80b0[968];
            *(longlong*)((longlong)local_87d0 + 584) = local_80b0[129];
            *(longlong*)((longlong)local_87d0 + 592) = local_80b0[1557];
            *(longlong*)((longlong)local_87d0 + 600) = local_80b0[1213];
            *(longlong*)((longlong)local_87d0 + 608) = local_80b0[849];
            *(longlong*)((longlong)local_87d0 + 616) = local_80b0[17];
            *(ulonglong*)(&local_87d0[312]) = local_80b0[1386];
            *(longlong*)((longlong)local_87d0 + 632) = local_80b0[617];
            *(longlong*)((longlong)local_87d0 + 64) =  local_80b0[1585];
            *(longlong*)((longlong)local_87d0 + 640) = local_80b0[107];
            *(ulonglong*)(&local_87d0[324]) = local_80b0[896];
            *(longlong*)((longlong)local_87d0 + 656) = local_80b0[239];
            *(longlong*)((longlong)local_87d0 + 664) = local_80b0[1161];
            *(longlong*)((longlong)local_87d0 + 672) = local_80b0[1328];
            *(longlong*)((longlong)local_87d0 + 680) = local_80b0[549];

            *(longlong*)((longlong)local_87d0 + 688) = local_80b0[1243];
            *(longlong*)((longlong)local_87d0 + 696) = local_80b0[430];
            *(longlong*)((longlong)local_87d0 + 704) = local_80b0[3651];
            *(longlong*)((longlong)local_87d0 + 712) = local_80b0[731];
            *(ulonglong*)(&local_87d0[36]) = local_80b0[1778];
            lVar6 = 0;
            
            do {
                uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
                *(int*)(local_8aa0 + lVar6 * 4) =
                    *(int*)((longlong)DAT_1809487d0 + uVar15) * *(int*)(local_87d0 + lVar6 * 4) +
                    *(int*)((longlong)DAT_1809487f0 + uVar15);
                lVar6 = lVar6 + 1;
            } while (lVar6 != 0x5a);
            Maybe_MEMSET_180512a50((char*)local_80b0, 0xaa, 0x168);
            var_st2 = *(longlong*)(p1_holder + 0xf20);
            pbVar24 = auStack364128;
            Maybe_MEMSET_180512a50((char*)pbVar24, 0xaa, 0x5a0);
            uVar15 = 0;
            do {
                lVar6 = -0x1b4a7e19b47e8e46;
                if (uVar15 < 0x5a) {
                    uVar19 = (ulonglong)((int)uVar15 * 4 & 0x1c);
                    uVar8 = (ulonglong)
                        ((*(int*)(local_8aa0 + uVar15 * 4) * *(int*)((longlong)DAT_180948810 + uVar19)
                            + *(int*)((longlong)DAT_180948830 + uVar19)) * -0x5d0ab7a9 + 0x91b1c2d0);
                    uVar19 = uVar8 * 0x45f41e6db4d7c39f + 0x153994a17deb3d76;
                    iVar22 = 8;
                    do {
                        uVar19 = (uVar19 >> 4) +
                            *(longlong*)(DAT_180948850 + (ulonglong)((uint)uVar19 & 0xf) * 8);
                        iVar22 = iVar22 + -1;
                    } while (iVar22 != 0);
                    lVar6 = uVar19 * -0x2075a18900000000 + uVar8 * -0x50df62973ed650e9 + 0x6adacee3f8e90cfc;
                }
                *(longlong*)(auStack364128 + uVar15 * 8) = lVar6;
                uVar15 = uVar15 + 1;
            } while (uVar15 != 0xb4);
            Maybe_MEMSET_180512a50((char*)local_87d0, 0xaa, 0x2d0);
            lVar6 = 0;
            do {
                uVar15 = (ulonglong)((int)lVar6 * 4 & 0x1c);
                uVar15 = (ulonglong)
                    ((*(int*)(p1_holder + lVar6 * 4 + 0x100) *
                        *(int*)((longlong)DAT_1809488d0 + uVar15) +
                        *(int*)((longlong)DAT_1809488f0 + uVar15)) * 0x71a67853 + 0x53be2ef0);
                uVar19 = uVar15 * -0x5af76ad9301def59 + 0x810275fd34063249;
                iVar22 = 8;
                do {
                    uVar19 = (uVar19 >> 4) + QWORD_180948910[(uint)uVar19 & 0xf];
                    iVar22 = iVar22 + -1;
                } while (iVar22 != 0);
                *(ulonglong*)(local_87d0 + lVar6 * 4) =
                    uVar19 * 0x1007791b00000000 + uVar15 * 0x5a49d42854b84f63 + 0x42a615fa5d5a7663;
                lVar6 = lVar6 + 1;
            } while (lVar6 != 0x5a);
            lVar6 = 0;
            tempqv = *(longlong*)auStack364128;
            do {
                lVar12 = tempqv *
                    ((longlong)var_st2 * -0x7a85192159826b7 + 0x7f571e3c4c3a4504) +
                    (longlong)var_st2 * 0x30d53418f8d9e7f6 + 0xa4d18c191b1bb6e;
                uVar15 = lVar12 * 0x6663cab3a43de5b + 0xc98f538072aa53e7;
                iVar22 = 7;
                do {
                    uVar15 = (uVar15 >> 4) +
                        *(longlong*)(DAT_180948990 + (ulonglong)((uint)uVar15 & 0xf) * 8);
                    iVar22 = iVar22 + -1;
                } while (iVar22 != 0);
                lVar20 = uVar15 * -0x215a740a50000000 + lVar12 * 0x3fbbb24709b210a7 + 0x298b9f1b2158eb0f;
                lVar12 = lVar20 * 0x660b7bacab2f7da2 + 0x2e6ca53a81eb830e;
                uVar15 = lVar20 * 0x8ff96d515ddd1e5 + 0x9d0a69061089c753;
                xmm0.assign8(uVar15);
                xmm0.PSHUFD(xmm0, 0x44);
                xmm1.assign8(lVar12);
                xmm1.PSHUFD(xmm1, 0x44);

                lVar20 = 0;
                do {
                    uVar19 = *(ulonglong*)(local_87d0 + lVar20 * 4);
                    uVar8 = *(ulonglong*)(local_87d0 + lVar20 * 4 + 4);
                    lVar2 = *(longlong*)((longlong)(pbVar24 + lVar20 * 8) + 8);

                    memcpy(xmm2.data, &local_87d0[lVar20 * 4], 16);
                    memcpy(xmm3.data, &pbVar24[lVar20 * 8], 16);
                    xmm3.PADDQ(xmm1);
                    memcpy(xmm4.data, xmm0.data, 16);
                    xmm4.PSRLQ(0x20);
                    xmm4.PMULUDQ(xmm2);
                    memcpy(xmm5.data, xmm2.data, 16);
                    xmm5.PSRLQ(0x20);
                    xmm5.PMULUDQ(xmm0);
                    xmm5.PADDQ(xmm4);
                    xmm5.PSLLQ(0x20);
                    xmm2.PMULUDQ(xmm0);
                    xmm2.PADDQ(xmm5);
                    xmm2.PADDQ(xmm3);
                    memcpy(&pbVar24[lVar20 * 8], xmm2.data, 16);
                    lVar20 = lVar20 + 2;
                } while (lVar20 != 0x5a);
                uVar15 = *(longlong*)(auStack364128 + lVar6 * 8) * 0x39a0d6bdcb5a26f1 + 0x92d8307ea4bfd0cd;
                iVar22 = 7;
                do {
                    uVar15 = (uVar15 >> 4) +
                        *(longlong*)(DAT_180948a10 + (ulonglong)((uint)uVar15 & 0xf) * 8);
                    iVar22 = iVar22 + -1;
                } while (iVar22 != 0);
                lVar12 = uVar15 * -0x713efdb0fe6604f3 + -0x11f8ff14a957fa05;
                uVar15 = lVar12 * -0x6ec8359368bd1ae1 + 0x21d97d0aaa4720e7;
                iVar22 = 9;
                do {
                    uVar15 = (uVar15 >> 4) +
                        *(longlong*)(DAT_180948a90 + (ulonglong)((uint)uVar15 & 0xf) * 8);
                    iVar22 = iVar22 + -1;
                } while (iVar22 != 0);
                tempqv=
                    (uVar15 * -0xec3f4b000000000 + lVar12 * -0x32e927f40703eeb) * -0x5c7981215ab9aaff +
                    *(longlong*)(auStack364128 + lVar6 * 8 + 8) + 0x4d6a91d06f7ea6ea;
                *(longlong*)(auStack364128 + lVar6 * 8 + 8) = tempqv;
                lVar6 = lVar6 + 1;
                pbVar24 = pbVar24 + 8;
            } while (lVar6 != 0x5a);
            lVar6 = 0x7a8f2c3a94248f2e;
            lVar12 = 0x5a;
            do {
                lVar20 = *(longlong*)(auStack364128 + lVar12 * 8) * -0x1e3af02da207fd9d +
                    lVar6 * -0x18ef54bb256ebec7 + 0x6b1ed5ec963e0df4;
                Maybe_MEMSET_180512a50((char*)local_8f90, 0xaa, 0x88);
                uVar15 = lVar20 * -0x28188843a2027e83 + 0xac5752094a6c6084;
                *(ulonglong*)local_8f90 = uVar15;
                lVar6 = 0;
                do {
                    uVar15 = (uVar15 >> 4) +
                        *(longlong*)(DAT_180948b10 + (ulonglong)((uint)uVar15 & 0xf) * 8);
                    *(ulonglong*)(local_8f90 + lVar6 * 8 + 8) = uVar15;
                    lVar6 = lVar6 + 1;
                } while (lVar6 != 0x10);
                uVar15 = (ulonglong)((int)lVar12 - 0x5aU & 7);
                lVar6 = *(longlong*)(&local_8f90[128]) * -0x2b91f7d000000000 + *(longlong*)(&local_8f90[56]) * -0x352b82856d46e083 +
                    0x5a6e60742808659a;
                if (lVar12 * 4 < 0x168)
                {
                    *(int*)(local_8220 + lVar12 * 4 + 8) =
                        ((int)*(longlong*)(&local_8f90[56]) * -0x50000000 + (int)lVar20 * -0x6b0f221f + 0x40d64549) *
                        *(int*)((longlong)DAT_180948b90 + uVar15 * 4) +
                        *(int*)((longlong)DAT_180948bb0 + uVar15 * 4);

                }
                else
                {
                    *(int*)((longlong)local_80b0+lVar12*4- 0x168)= ((int)*(longlong*)(&local_8f90[56]) * -0x50000000 + (int)lVar20 * -0x6b0f221f + 0x40d64549) *
                        *(int*)((longlong)DAT_180948b90 + uVar15 * 4) +
                        *(int*)((longlong)DAT_180948bb0 + uVar15 * 4);
                }
                lVar12 = lVar12 + 1;
            } while (lVar12 != 0xb4);
            ConstMultiplier_18019c629
            (p1_holder, (longlong)local_9270, (longlong)local_80b0, (longlong)out);

            return;
        }
    } while (true);
}





Integer HasMulAdc_18016d24d(byte* param_1, byte* param_2, byte* param_3, byte* param_4, byte * param_5,byte * out)

{
    uint local_320[0x168/4];
    uint local_490[0x168/4];
    char local_a980[0x5a0];
    char local_b980[0x40e];
    char local_9180[0x5a0];
    byte local_d80[1800];
    byte local_e80[1800];
    byte local_a80[1800];
    byte local_b80[1800];
    byte local_c80[1800];
    byte local_980[1800];
    byte local_1b0[1800];
    uint local_f80[1800];
    //param_4 is param_5
    byte* ttmp = param_4;
    param_4 = param_5;
    param_5 = ttmp;
    Maybe_MEMSET_180512a50((char*)local_320, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_490, 0xaa, 0x168);
    Maybe_MEMSET_180512a50((char*)local_a980, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50(local_b980, 0xaa, 0x40e);
    ConstUser_18016b077(0x40e00001b259, (byte*)param_4, (byte*)param_4,(byte *) local_b980);
    Maybe_MEMSET_180512a50(local_9180, 0xaa, 0x5a0);
    int lVar3 = 0;
    int iVar37 = 0;
    int lVar7;
    do {
        lVar7 = iVar37;
        undefined4 uVar26 = *(undefined4*)(local_b980 + lVar7 + 4);
        undefined4 uVar27 = *(undefined4*)(local_b980 + lVar7 + 8);
        undefined4 uVar28 = *(undefined4*)(local_b980 + lVar7 + 0xc);
        *(undefined4*)(local_9180 + lVar3) = *(undefined4*)(local_b980 + lVar7);
        *(undefined4*)(local_9180 + lVar3 + 4) = uVar26;
        *(undefined4*)(local_9180 + lVar3 + 8) = uVar27;
        *(undefined4*)(local_9180 + lVar3 + 12) = uVar28;
        iVar37 = iVar37 + 0xe;
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x4a0);
    lVar3 = 0;
    do {
        MB_Zeropad_180113d26(0x80, DAT_18091a550, 0x80, (byte *)(local_9180 + lVar3+ 0x4a0));
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x100);
    lVar3 = 0;
    do {
        ConstUser_18016b077(0x1000002cd3a, (byte *) (local_9180 + lVar3),(byte *) (local_9180 + lVar3), (byte *)(local_a980 + lVar3));
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x5a0);
    lVar3 = 0;
    reg16 xmm9;
    {
        unsigned char dt[16]= { 4, 4,7,1,3,3,1,1,2,5,1,3,7,7,7,7 };
        memcpy(xmm9.data, dt,16);
    }
   ulonglong  local_ba58 = 0x120000054d6;
   ulonglong  local_ba50 = 0x801000002f6b6;
   ulonglong  local_ba30 = 0x12000019c5e;
   ulonglong  local_ba70 = 0x12000027448;
   byte* pbVar1 = NULL;
   reg16 xmm7;
   memset(xmm7.data, 0, 16);
   reg16 xmm8;
   {
       unsigned char dt[16] = { 1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1  };
       memcpy(xmm8.data, dt, 16);
   }
   reg16 xmm10;
   xmm10.PSHUFD(xmm8, 0xf5);
   reg16 xmm0, xmm1;
    do {

        int uVar8 = (ulonglong)((uint)lVar3 & 7);
        int local_ba60 = uVar8 * 9; 
        memcpy(local_980, xmm9.data, 16);
        *(short*)&local_980[16] = 0x0201;
        int local_ba68 = lVar3;
        ConstUser_18016b077(local_ba58, DAT_18091a430 + uVar8 * 0x12, DAT_18091a430 + uVar8 * 0x12,
            (byte *)local_9180);
        OtherConstUser_180169484
        (local_ba50, (byte*)(local_a980 + lVar3 * 0x10),
            (byte*)(local_a980 + lVar3 * 0x10), (byte*)local_b980);
        ConstUser_18016b077(local_ba30, (byte*)local_9180, (byte*)local_9180, local_1b0);
        int iVar11 = 0x1c;
        do {

            ConstUser_18016b077(local_ba70, (byte *) local_b980, local_980, local_a80);
            PFUN_180119595((uint*)INT_18091a580, (uint*)INT_18136f6d4, 5, 0x53365e6c);
            ConstUser_18016b077(0x1200002b000, (byte *)INT_18136f6d4, local_a80, local_b80);
            ConstUser_18016b077(0x1200000f42b, (byte*)local_9180, local_b80, local_c80);
            ConstUser_18016b077(0x1200002da46, local_1b0, local_c80, local_1b0);
            ConstUser_18016b077(0x12000036217, (byte*) local_9180, (byte*)local_9180, (byte*)local_9180);
            ConstUser_18016b077(0x12000020841, local_980, local_980, local_980);
            iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        ConstUser_18016b077(0x1200003450d, local_1b0, (byte *) local_9180, local_d80);
        ConstUser_18016b077(0x12000016c06, local_d80, DAT_18091a4c0 + local_ba60 * 2, local_e80);
        ConstUser_18016b077(0x12000026a1b, local_e80, local_e80, (byte *)local_9180);
        *(short*)&local_9180[16] = *(short*)&local_9180[16] & 0x3ff;
        local_f80[0] = 0;
        int bVar2 = 0;
        uVar8 = 0;
        do {
            pbVar1 = (byte*)((longlong)local_f80 + (uVar8 >> 2));
            *pbVar1 = *pbVar1 | (local_9180[uVar8 + 2] & 3) << (bVar2 & 6);
            uVar8 = uVar8 + 1;
            bVar2 = bVar2 + 2;
        } while (uVar8 != 0x10);
       
        xmm0.assign4(local_f80[0]);
        xmm0.PUNPCKLBW(xmm7);
        xmm0.PUNPCKLWD(xmm7);
        xmm1.PSHUFD(xmm0, 0xf5);
        xmm0.PMULUDQ(xmm8);
        xmm0.PSHUFD(xmm0, 0xe8);
        xmm1.PMULUDQ(xmm10);
        xmm1.PSHUFD(xmm1, 0xe8);
        xmm0.PUNPCKLDQ(xmm1);
        xmm1.PSHUFD(xmm0, 0xee);
        xmm1.POR(xmm0);
        xmm0.PSHUFD(xmm1, 0x55);
        xmm0.POR(xmm1);

        *(uint32_t*)&local_320[local_ba68] = *(uint32_t*)&xmm0.data[0];
        lVar3 = local_ba68 + 1;
    } while (lVar3 != 0x5a);

    Integer i0 = Integer((byte*)local_320,  0x5a*4, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    Maybe_MEMSET_180512a50((char*)local_a980, 0xaa, 0x5a0);
    Maybe_MEMSET_180512a50(local_b980, 0xaa, 0x40e);
    ConstUser_18016b077(0x40e000032dca, param_5, param_5, (byte *) local_b980);
    Maybe_MEMSET_180512a50(local_9180, 0xaa, 0x5a0);
    lVar3 = 0;
    int iVar11 = 0;
    do {
        lVar7 = (longlong)iVar11;
        undefined4 uVar32 = *(undefined4*)(local_b980 + lVar7 + 4);
        undefined4 uVar33 = *(undefined4*)(local_b980 + lVar7 + 8);
        undefined4  uVar34 = *(undefined4*)(local_b980 + lVar7 + 0xc);
        *(undefined4*)(local_9180 + lVar3) = *(undefined4*)(local_b980 + lVar7);
        *(undefined4*)(local_9180 + lVar3 + 4) = uVar32;
        *(undefined4*)(local_9180+ lVar3 + 8) = uVar33;
        *(undefined4*)(local_9180 + lVar3 + 12) = uVar34;
        iVar11 = iVar11 + 0xe;
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x4a0);
    lVar3 = 0;
    do {
        MB_Zeropad_180113d26(0x80, DAT_18091a6c0, 0x80, (byte *)(local_9180 + lVar3+ 0x4a0));
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x100);
    lVar3 = 0;
    do {
        ConstUser_18016b077(0x100000016b0, (byte *)(local_9180 + lVar3),(byte *) (local_9180 + lVar3), (byte *) local_a980 + lVar3);
        lVar3 = lVar3 + 0x10;
    } while (lVar3 != 0x5a0);
    int  uVar8 = 0;

    {
        unsigned char dt[16] = { 3, 3,1,1,3,1,3,1, 3,2,6,4,6,0,5,2 };
        memcpy(xmm9.data, dt, 16);
    }
    memset(xmm7.data, 0, 16);

    ulonglong local_ba60 = 0x120000353ea;
    local_ba58 = 0x1200001bb11;
    do {
        int uVar6 = (ulonglong)((uint)uVar8 & 7);
        int local_ba68 = uVar6 * 9;
        local_f80[0] = 0xaaaaaaaa;
        memcpy(local_980, xmm9.data, 16);
        *(short*)&local_980[16] = 0x705;
        local_ba70 = uVar8;
        ConstUser_18016b077(local_ba60, DAT_18091a5a0 + uVar6 * 0x12, DAT_18091a5a0 + uVar6 * 0x12,
            (byte*) local_9180);
        OtherConstUser_180169484
        (0x8010000014195, (byte*)(local_a980 + uVar8 * 0x10),
            (byte*)(local_a980 + uVar8 * 0x10), (byte*)local_b980);
        ConstUser_18016b077(local_ba58, (byte *) local_9180, (byte*)local_9180, local_1b0);
        iVar11 = 0x1c;
        do {
            ConstUser_18016b077(0x1200000001c, (byte*)local_b980, local_980, local_a80);
            PFUN_180119595((uint*)DAT_18091a6f0, (uint*)DAT_18136f6ec, 5, 0xc670c1b4);
            ConstUser_18016b077(0x12000013c44, DAT_18136f6ec, local_a80, local_b80);
            ConstUser_18016b077(0x1200000d1a8, (byte*)local_9180, local_b80, local_c80);
            ConstUser_18016b077(0x12000006e8a, local_1b0, local_c80, local_1b0);
            ConstUser_18016b077(0x12000016696, (byte*)local_9180, (byte*)local_9180, (byte*)local_9180);
            ConstUser_18016b077(0x12000020551, local_980, local_980, local_980);
            iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        ConstUser_18016b077(0x12000026ac5, local_1b0, (byte*)local_9180, local_d80);
        ConstUser_18016b077(0x12000034487, local_d80, DAT_18091a630 + local_ba68 * 2, local_e80);
        ConstUser_18016b077(0x1200002d292, local_e80, local_e80, (byte*) local_9180);
        *(short*)&local_9180[16] = *(short*)&local_9180[16] & 0x3ff;
        local_f80[0] = 0;
        int  bVar2 = 0;
        uVar8 = 0;
        do {
            pbVar1 = (byte*)((longlong)local_f80 + ((uVar8 & 0xffffffff) >> 2));
            *pbVar1 = *pbVar1 | (local_9180[uVar8 + 2] & 3) << (bVar2 & 6);
            uVar8 = uVar8 + 1;
            bVar2 = bVar2 + 2;
        } while (uVar8 != 0x10);
        xmm0.assign4(local_f80[0]);
        xmm0.PUNPCKLBW(xmm7);
        xmm0.PUNPCKLWD(xmm7);
        xmm1.PSHUFD(xmm0, 0xf5);
        xmm0.PMULUDQ(xmm8);
        xmm0.PSHUFD(xmm0, 0xe8);
        xmm1.PMULUDQ(xmm10);
        xmm1.PSHUFD(xmm1, 0xe8);
        xmm0.PUNPCKLDQ(xmm1);
        xmm1.PSHUFD(xmm0, 0xee);
        xmm1.POR(xmm0);
        xmm0.PSHUFD(xmm1, 0x55);
        xmm0.POR(xmm1);
        local_490[local_ba70] = *((uint32_t*)&xmm0.data[0]);
        uVar8 = (int)local_ba70 + 1;
    } while (uVar8 != 0x5a);
    Integer i2 = Integer((byte*)local_490, 0x5a * 4, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    ManyMutiplies_1801720e0
    (param_1, param_2, param_3, (byte*)local_320, (byte*)local_490, local_980);
 
    Maybe_MEMSET_180512a50((char*)local_9180, 0xaa, 0x402);
    ConstUser_18016b077(0x40200001d6e6, local_980, local_980, (byte*) local_9180);
    local_9180[1025] = local_9180[1025] & 3;
    int bVar2 = 0;
    Maybe_MEMSET_180512a50(local_a80, 0, 0x100);
    uVar8 = 0;
    do {
        local_a80[(uVar8 & 0xffffffff) >> 2] =
            local_a80[(uVar8 & 0xffffffff) >> 2] | (local_9180[uVar8 + 2] & 3) << (bVar2 & 6);
        uVar8 = uVar8 + 1;
        bVar2 = bVar2 + 2;
    } while (uVar8 != 0x400);
    Integer int1 = Integer(local_a80, 0x100, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
  
    ModularArithmetic ma(main_n);
    Integer t1=ma.Exponentiate(int1, sec_pwr);
    t1 = ma.Multiply(t1,sec_mul);
    t1.Encode(out,256,Integer::UNSIGNED);
    t1 = ma.Exponentiate(t1, 65537);
    return t1;
}
Integer Longstringproc(byte * out)
{
    byte local_270[82];
    byte local_678[0x402];
    byte local_a80[0x402];
    byte local_e90[0x40e];
    byte local_12a0[0x40e];
    Crazery_18016c0bb((char*)local_270, local_678, local_a80, local_e90, local_12a0);
    byte local_1aa8[0x802];
    byte local_22b0[0x802];
    OtherConstUser_180169484(0x10004020000345e1, local_678, local_678, local_1aa8);
    OtherConstUser_180169484(0x1000402000007410, local_a80, local_a80, local_22b0);
   return  HasMulAdc_18016d24d(DAT_0f030174201, local_1aa8, local_22b0, local_e90, local_12a0, out);


}



void freeStr(void* str) {
  free(str);
}
#define NEW_C_STR(str) (strdup((str).c_str()))

const char * guessInput(const char * input)
{
    hex2bin(input,(char*)__metaSafetable);
    byte out[0x200];
    Integer inp=Longstringproc(out);
    byte outp[256];
    inp.Encode(outp, 256,Integer::UNSIGNED);
    return NEW_C_STR(hexStr(outp,256));
}
const char* getOutput(const char* input)
{
    hex2bin(input,(char*)__metaSafetable);
    byte out[0x200];
    Longstringproc(out);
    return NEW_C_STR(hexStr(out,256));
}

enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};

#define SHA1HashSize 20

typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest  */

    uint32_t Length_Low;            /* Message length in bits      */
    uint32_t Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];      /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;


#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))



int SHA1Reset(SHA1Context* context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;

    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = 0;

    return shaSuccess;
}


void SHA1ProcessMessageBlock(SHA1Context* context)
{
    const uint32_t K[] = {       /* Constants defined in SHA-1   */
                            0x5A827999,
                            0x6ED9EBA1,
                            0x8F1BBCDC,
                            0xCA62C1D6
    };
    int           t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
    uint32_t      W[80];             /* Word sequence               */
    uint32_t      A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    for (t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for (t = 0; t < 20; t++)
    {
        temp = SHA1CircularShift(5, A) +
            ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5, A) +
            ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}


void SHA1PadMessage(SHA1Context* context)
{
      if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while (context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}


int SHA1Result(SHA1Context* context,
    uint8_t Message_Digest[SHA1HashSize])
{
    int i;

    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for (i = 0; i < 64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }

    for (i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i >> 2]
            >> 8 * (3 - (i & 0x03));
    }

    return shaSuccess;
}

int SHA1Input(SHA1Context* context,
    const uint8_t* message_array,
    unsigned       length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;
        return shaStateError;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    while (length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
            (*message_array & 0xFF);

        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}

void mgf1(byte* buf, size_t blen, byte* out, size_t outlen)
{
    SHA1Context sha;
    size_t len = outlen / SHA1HashSize;
    if (outlen % SHA1HashSize != 0) len++;
    size_t remlen = outlen;
    for (unsigned int i = 0; i < len; i++)
    {
        byte rm[4];
        byte digest[SHA1HashSize];
        rm[0] = (i >> 24) & 0xff;
        rm[1] = (i >> 16) & 0xff;
        rm[2] = (i >> 8) & 0xff;
        rm[3] = (i ) & 0xff;
        SHA1Reset(&sha);
        SHA1Input(&sha, (const unsigned char*)buf, blen);
        SHA1Input(&sha, (const unsigned char*)rm, 4);
        SHA1Result(&sha, digest);
        if (remlen >= SHA1HashSize)
        {
            memcpy(&out[i * SHA1HashSize], digest, SHA1HashSize);
            remlen -= SHA1HashSize;
        }
        else
        {
            memcpy(&out[i * SHA1HashSize], digest, remlen);
            break;
        }
    }
}
//from rfc8017, abridged
/*
      1.  Length checking:
          b.  If the length of the ciphertext C is not k octets, output
              "decryption error" and stop.
          c.  If k < 2hLen + 2, output "decryption error" and stop.

      3.  EME-OAEP decoding:

          a.  If the label L is not provided, let L be the empty string.
              Let lHash = Hash(L), an octet string of length hLen (see
              the note in Section 7.1.1).

          b.  Separate the encoded message EM into a single octet Y, an
              octet string maskedSeed of length hLen, and an octet
              string maskedDB of length k - hLen - 1 as

                 EM = Y || maskedSeed || maskedDB.

          c.  Let seedMask = MGF(maskedDB, hLen).
          d.  Let seed = maskedSeed \xor seedMask.
          e.  Let dbMask = MGF(seed, k - hLen - 1).
          f.  Let DB = maskedDB \xor dbMask.
          g.  Separate DB into an octet string lHash' of length hLen, a
              (possibly empty) padding string PS consisting of octets
              with hexadecimal value 0x00, and a message M as
                 DB = lHash' || PS || 0x01 || M.
              If there is no octet with hexadecimal value 0x01 to
              separate PS from M, if lHash does not equal lHash', or if
              Y is nonzero, output "decryption error" and stop.  (See
              the note below.)
      4.  Output the message M.
*/
const char* deoaep(byte* input, size_t len)
{
    if (len < SHA1HashSize * 2 + 2)
    {
        //Message too short
        return strdup("");
    }
    if (len >256)
    {
        //Message too long
        return strdup("");
    }
    if (input[0] != 0)
    {
        //Invalid oaep prefix
        return strdup("");

    }
    byte seed[SHA1HashSize];
    memcpy(seed, &input[1], SHA1HashSize);
    byte seedmask[SHA1HashSize];
    mgf1(&input[1 + SHA1HashSize], len - SHA1HashSize - 1, seedmask, SHA1HashSize);
    for (int i = 0; i < SHA1HashSize; i++)
    {
        seed[i] ^= seedmask[i];
    }
    byte msg[256];
    mgf1(seed, SHA1HashSize, msg, len - SHA1HashSize - 1);
    for (int i = 0; i < len - SHA1HashSize - 1; i++)
    {
        msg[i] ^= input[i+ SHA1HashSize + 1];
    }
    int offs = SHA1HashSize;
    while (msg[offs]!=1)
    {
        if (msg[offs] != 0)
        {
            //Invalid oaep encoding
            return strdup("");
        }
        offs++;
    }
    offs++;
    return strdup(hexStr(&msg[offs], len - SHA1HashSize - 1 - offs).c_str());
}
const char* getDeoaep(const char* input)
{
    hex2bin(input,(char*)__metaSafetable);
    byte out[0x200];
    Longstringproc(out);
    return deoaep(out,256);
}

const char* tryUsingDecoder(const char* input)
{
   std::string k(input);
   for (int i = 0; i < 1024; i++)
    {
        if(i/2>=k.length())
        __metaSafetable[i] = 0;
        else
        {
            int pos = char2int(k[k.length() - (i / 2) - 1]);
            if (i % 2)
            {
                pos >>= 2;
            }
            else
            {
                pos &= 3;
            }
            __metaSafetable[i] = pos;
        }
    }
    byte out[0x200];
    Longstringproc(out);
    return deoaep(out,256);
}