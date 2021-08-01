// this is just for information purposes

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
void Fill_1c8_buffer_18016ae81(SHA1_buf* param_1)

{
    param_1->flag = '\0';
    param_1->prehash = 0;
    param_1->offs = 0;
    param_1->counter = 0;
    PFUN_180119595((uint*)DAT_180909f00, (uint*)DAT_1812f159c, 5, 0x7f041f7e);
    PFUN_180119595((uint*)DAT_180909f00, (uint*)DAT_1812f159c, 5, 0x7f041f7e);
    ConstUser_18016b077(0x12000038a82, DAT_1812f159c, DAT_1812f159c, param_1->encoded1);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x20), (uint*)DAT_1812f15b4, 5, 0x664c72d4);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x20), (uint*)DAT_1812f15b4, 5, 0x664c72d4);
    ConstUser_18016b077(0x12000005c9f, DAT_1812f15b4, DAT_1812f15b4, param_1->encoded2);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x40), (uint*)DAT_1812f15cc, 5, 0x411ef068);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x40), (uint*)DAT_1812f15cc, 5, 0x411ef068);
    ConstUser_18016b077(0x120000274c6, DAT_1812f15cc, DAT_1812f15cc, param_1->encoded3);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x60), (uint*)DAT_1812f15e4, 5, 0x6c9bcfd7);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x60), (uint*)DAT_1812f15e4, 5, 0x6c9bcfd7);
    ConstUser_18016b077(0x1200001c358, DAT_1812f15e4, DAT_1812f15e4, param_1->encoded4);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x80), (uint*)DAT_1812f15fc, 5, 0x80487993);
    PFUN_180119595((uint*)(DAT_180909f00 + 0x80), (uint*)DAT_1812f15fc, 5, 0x80487993);
    ConstUser_18016b077(0x1200000b2ff, DAT_1812f15fc, DAT_1812f15fc, param_1->encoded5);
    return;
}


/* WARNING: Could not reconcile some variable overlaps */

void Insha1_3_18019ba88(byte* param_1, byte* param_2)

{
    byte* pbVar1;
    short uVar2;
    short uVar3;
    short uVar4;
    byte bVar5;
    byte bVar6;
    longlong lVar8;
    byte* pbVar9;
    byte* pbVar10;
    ulonglong uVar11;
    byte* local_830;
    byte* local_828;
    byte* local_820;
    byte* local_818;
    byte* local_810;
    byte* local_808;
    byte* local_800;
    byte local_7f8[18];
    byte local_7d8[18];
    byte local_7b8[18];
    byte local_798[18];
    byte local_778[18];
    byte local_758[18];
    byte local_738[18];
    byte local_718[18];
    byte local_6f8[18];
    byte local_6d8[18];
    byte local_6b8[1440];
    byte local_118[18];
    byte local_f8[34];
    byte local_c8[34];
    byte local_98[18];
    byte local_78[18];
    pbVar9 = local_6b8;
    local_828 = param_2;
    local_800 = param_1;
    Maybe_MEMSET_180512a50((char*)pbVar9, 0xaa, 0x5a0);
    lVar8 = 0;
    local_830 = (byte*)0x22008008959;
    local_808 = (byte*)0x12000012381;
    local_810 = (byte*)0x1200401087b;
    local_818 = (byte*)0x1200001ef9d;
    local_820 = (byte*)0x12004008a68;
    do {
        pbVar1 = local_828 + lVar8;
        ConstUser_18016b077(0x2200001f7d6, pbVar1, pbVar1, local_c8);
        OtherConstUser_180169484((ulonglong)local_830, pbVar1, pbVar1, local_f8);
        ConstUser_18016b077((ulonglong)local_808, local_c8, local_c8, pbVar9 + 0x36);
        OtherConstUser_180169484((ulonglong)local_810, local_c8, local_c8, pbVar9 + 0x24);
        ConstUser_18016b077((ulonglong)local_818, local_f8, local_f8, pbVar9 + 0x12);
        OtherConstUser_180169484((ulonglong)local_820, local_f8, local_f8, pbVar9);
        pbVar9 = pbVar9 + 0x48;
        lVar8 = lVar8 + 0x42;
    } while (lVar8 != 0x108);
    pbVar9 = local_6b8;
    lVar8 = 0x40;
    local_828 = (byte*)0x1200000bf63;
    local_830 = (byte*)0x12000005b82;
    do {
        ConstUser_18016b077((ulonglong)local_828, pbVar9 + 0xea, pbVar9 + 0x90, local_c8);
        ConstUser_18016b077((ulonglong)local_830, pbVar9 + 0x24, pbVar9, local_f8);
        ConstUser_18016b077(0x1200001aaf2, local_c8, local_f8, local_798);
        OtherConstUser_180169484(0x40002004006ef2, local_798, local_798, local_78);
        ConstUser_18016b077(0x1200001ab1d, local_798, local_798, local_98);
        ConstUser_18016b077(0x12000002274, local_98, local_78, pbVar9 + 0x120);
        pbVar1 = local_800;
        pbVar9 = pbVar9 + 0x12;
        lVar8 = lVar8 + -1;
    } while (lVar8 != 0);
    ConstUser_18016b077(0x1200002cb15, local_800, local_800, local_6d8);
    local_808 = pbVar1 + 0x12;
    ConstUser_18016b077(0x1200000982a, local_808, local_808, local_6f8);
    local_810 = pbVar1 + 0x24;
    ConstUser_18016b077(0x120000094ff, local_810, local_810, local_718);
    local_818 = pbVar1 + 0x36;
    ConstUser_18016b077(0x12000023625, local_818, local_818, local_738);
    local_820 = pbVar1 + 0x48;
    ConstUser_18016b077(0x1200002d8c2, local_820, local_820, local_758);
    local_830 = local_6b8;
    uVar11 = 0;
    ulonglong ecounter = 0;
    do {
        bVar6 = local_78[15];
        bVar5 = local_78[14];
        uVar4 = *(short*)(&local_78[8]);
        uVar3 = *(short*)(&local_78[6]);
        uVar2 = *(short*)(&local_78[0]);
        pbVar9 = local_c8;
        ecounter = uVar11;
        if (uVar11 < 0x14) {
            ConstUser_18016b077(0x1200002f637, local_6f8, local_718, local_c8);
            ConstUser_18016b077(0x1200002cd8b, local_738, local_6f8, local_f8);
            ConstUser_18016b077(0x12000011455, local_f8, local_738, local_78);
            uVar11 = 0x12000002894;
        LAB_18019c074:
            pbVar10 = local_78;
        }
        else {
            if ((int)uVar11 - 0x28U < 0x14) {
                ConstUser_18016b077(0x120000190a8, local_6f8, local_718, local_c8);
                ConstUser_18016b077(0x12000022e36, local_6f8, local_738, local_f8);
                ConstUser_18016b077(0x1200001f053, local_718, local_738, local_78);
                pbVar9 = local_98;
                ConstUser_18016b077(0x120000226ed, local_c8, local_f8, pbVar9);
                uVar11 = 0x1200002240f;
                goto LAB_18019c074;
            }
            *(short*)(&local_78[0]) = uVar2;
            *(short*)(&local_78[6]) = uVar3;
            *(short*)(&local_78[8]) = uVar4;
            local_78[14] = bVar5;
            local_78[15] = bVar6;
            ConstUser_18016b077(0x12000018aef, local_6f8, local_718, local_c8);
            uVar11 = 0x12000024d7e;
            pbVar10 = local_738;
        }
        ConstUser_18016b077(uVar11, pbVar9, pbVar10, local_778);
        OtherConstUser_180169484(0x3800400381c904, local_6d8, local_6d8, local_c8);
        ConstUser_18016b077(0x12000001673, local_6d8, local_6d8, local_98);
        memcpy(&local_78[2], local_98, 16);
        *(short*)(&local_78[0]) = 0x400;
        ConstUser_18016b077(0x12000009845, local_78, local_78, local_f8);
        ConstUser_18016b077(0x12000032d81, local_f8, local_c8, local_798);
        ConstUser_18016b077(0x12000010fc1, local_798, local_778, local_7b8);
        ConstUser_18016b077(0x12000016028, local_7b8, local_758, local_7d8);
        ConstUser_18016b077(0x1200000d2c3, local_7d8,
            DAT_18090a380 + (ulonglong)((byte)ecounter / 0x14) * 0x12, local_7f8);
        pbVar9 = local_830;
        ConstUser_18016b077(0x1200002da7a, local_7f8, local_830, local_118);
        ConstUser_18016b077(0x120000235dc, local_738, local_738, local_758);
        ConstUser_18016b077(0x12000023b3f, local_718, local_718, local_738);
        OtherConstUser_180169484(0x401100040a036, local_6f8, local_6f8, local_98);
        local_78[17] = local_6f8[2];
        short eax = *(short*)local_6f8;
        *(short*)(&local_78[15]) = eax;
        local_78[14] = 2;
        memset(local_78, 0, 14);
        ConstUser_18016b077(0x1200001c19f, local_78, local_78, local_c8);
        ConstUser_18016b077(0x12000018a77, local_c8, local_98, local_718);
        ConstUser_18016b077(0x12000025968, local_6d8, local_6d8, local_6f8);
        ConstUser_18016b077(0x12000009446, local_118, local_118, local_6d8);
        uVar11 = (longlong)ecounter + 1;
        local_830 = pbVar9 + 0x12;
        if (uVar11 == 0x50) {
            ConstUser_18016b077(0x1200001e5a2, local_800, local_6d8, local_800);
            ConstUser_18016b077(0x120000106ed, local_808, local_6f8, local_808);
            ConstUser_18016b077(0x1200002448c, local_810, local_718, local_810);
            ConstUser_18016b077(0x1200000df3a, local_818, local_738, local_818);
            ConstUser_18016b077(0x1200003343a, local_820, local_758, local_820);
            return;
        }
    } while (true);
}

void Insha1_2_18016b6f0(byte* param_1, uint param_2, SHA1_buf* param_3)

{
    uint uVar2;
    uint uVar3;
    uint uVar4;
    uint local_fc;
    byte auStack248[66];
    byte local_a8[66];

    if (param_2 != 0) {
        uVar3 = *(uint*)&param_3->offs & 0xf;
        if (uVar3 == 0) {
            ConstUser_18016b077(0x42000003d12, param_1, param_1, (byte*)param_3->encbytes[param_3->counter])
                ;
        }
        else {
            uVar4 = 0xaaaaaaaa;
            local_fc = param_2;
            ConstUser_18016b077(0x420000080fc, param_1, param_1, local_a8);
            uVar2 = uVar3;
            do {
                OtherConstUser_180169484(0x1003e001030691, local_a8, local_a8, local_a8);
                uVar2 = uVar2 - 1;
            } while (uVar2 != 0);
            ConstUser_18016b077(0x4200001047b, (byte*)param_3->encbytes[param_3->counter],
                DAT_180909fa0 + (ulonglong)(uVar3 ^ 0xf) * 0x42, auStack248);
            ConstUser_18016b077(0x420000230a2, auStack248, local_a8,
                (byte*)param_3->encbytes[param_3->counter]);
            param_2 = local_fc;
        }
        if (0x10 - uVar3 <= param_2) {
            uVar2 = param_3->counter + 1;
            param_3->counter = uVar2;
            if (uVar2 == 4) {
                Insha1_3_18019ba88(param_3->encoded1, (byte*)param_3->encbytes);
                param_3->counter = 0;
            }
            if (0x10 - uVar3 < param_2) {
                ConstUser_18016b077(0x4200000947d, param_1, param_1, auStack248);
                uVar3 = uVar3 | 0xfffffff0;
                do {
                    memcpy(&(local_a8[4]), auStack248, 62);
                    *(uint*)(&local_a8[0]) = 0x4000000;
                    ConstUser_18016b077(0x42000002cae, local_a8, local_a8, auStack248);
                    uVar3 = uVar3 + 1;
                } while (uVar3 != 0);
                ConstUser_18016b077(0x420000379f0, auStack248, auStack248,
                    (byte*)param_3->encbytes[param_3->counter]);
            }
        }
        param_3->offs = param_3->offs + (ulonglong)param_2;
    }
    return;
}


void Insha1_1_18016aceb(byte* param_1, uint param_2, SHA1_buf* param_3)

{
    longlong lVar1;
    byte bVar2;
    ulonglong uVar3;
    byte* pbVar4;
    uint uVar5;
    undefined4 uVar10;
    undefined4 uVar11;
    undefined4 uVar12;
    undefined4 uVar13;
    SHA1_buf* local_130;
    byte local_128[16];
    byte local_118[66];
    byte local_c8[16];
    byte local_b8[66];
   
    local_130 = param_3;
    if (param_2 != 0) {
        uVar10 = 0;
        uVar11 = 0;
        uVar12 = 0;
        uVar13 = 0;
        do {
            uVar5 = 0x10;
            if (param_2 < 0x10) {
                uVar5 = param_2;
            }
            if (0x10 - uVar5 != 0) {
                Maybe_MEMSET_180512a50((char*)local_c8, 0, (ulonglong)(0x10 - uVar5));
            }
            uVar3 = 0xf;
            pbVar4 = param_1;
            do {
                local_c8[uVar3 & 0xffffffff] = *pbVar4;
                lVar1 = uVar5 + uVar3;
                uVar3 = uVar3 - 1;
                pbVar4 = pbVar4 + 1;
            } while (lVar1 != 0x10);
            memcpy(local_128, local_c8, 16);
            memset(local_b8, 0, sizeof(local_b8));
            *(short*)local_b8 = 0x104;
            bVar2 = 0;
            uVar3 = 0;
            do {
                local_b8[uVar3 + 2] = local_128[(uVar3 & 0xffffffff) >> 2] >> (bVar2 & 6) & 3;
                uVar3 = uVar3 + 1;
                bVar2 = bVar2 + 2;
            } while (uVar3 != 0x40);
            ConstUser_18016b077(0x420000205c8, local_b8, local_b8, local_118);
            Insha1_2_18016b6f0(local_118, uVar5, local_130);
            param_1 = param_1 + uVar5;
            param_2 = param_2 - uVar5;
        } while (param_2 != 0);
    }
    return;
}
void Encode_Buffer_Const_18016b14f(SHA1_buf* param_1)

{
    byte local_68[18];

    if (param_1->flag != '\0') {
        param_1->flag = '\0';
       
        //uVar28 = param_1->hash1;
        *(short*)local_68 = 0x405;
        uint tmp= param_1->hash1;
        for (int i = 0; i < 16; i++)
        { 
            local_68[2 + i] = tmp & 3;
            tmp >>= 2;
       }
        //probably same unpack (2 bits per byte) as in other places...)  TODO... 
        ConstUser_18016b077(0x12000028fff, local_68, local_68, param_1->encoded1);
        byte tb[18];
        byte tl[18];
        ConstUser_18016b077(0x12000004b51, param_1->encoded1, param_1->encoded1, tb);
        memset(tl, 0, 18);
        //*(short*)tl = 0x405;
        //x36409'
        //31e6'
        //ConstUser_18016b077(0x12000004b51, tl,tl, tb);
        ConstUser_18016b077(0x1200001b218, tl, tl, tb);
        uint tst=0;
        for (int i = 2; i < 18; i++)
        {
            tst += tb[i] << ((i - 2) * 2);
        }

        *(short*)local_68 = 0x05;
        tmp = param_1->hash2;
        for (int i = 0; i < 16; i++)
        {
            local_68[2 + i] = tmp & 3;
            tmp >>= 2;
        }
        ConstUser_18016b077(0x12000015b7f, local_68, local_68, param_1->encoded2);
        *(short*)local_68 = 0x401;
        tmp = param_1->hash3;
        for (int i = 0; i < 16; i++)
        {
            local_68[2 + i] = tmp & 3;
            tmp >>= 2;
        }
        ConstUser_18016b077(0x12000036409, local_68, local_68, param_1->encoded3);
        *(short*)local_68 = 0x102;
        tmp = param_1->hash4;
        for (int i = 0; i < 16; i++)
        {
            local_68[2 + i] = tmp & 3;
            tmp >>= 2;
        }
        ConstUser_18016b077(0x12000020661, local_68, local_68, param_1->encoded4);
        *(short*)local_68 = 0x5;
        tmp = param_1->hash5;
        for (int i = 0; i < 16; i++)
        {
            local_68[2 + i] = tmp & 3;
            tmp >>= 2;
        }
        
        ConstUser_18016b077(0x120000031e6, local_68, local_68, param_1->encoded5);
        Insha1_1_18016aceb((byte*)param_1->workspace, param_1->prehash, param_1);
        param_1->prehash = 0;
    }
    return;
}



unsigned char DAT_18053c6c0[16] = { 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 };
unsigned char DAT_18064cd50[16] = { 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
unsigned char DAT_18064cda0[16] = { 0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63 };
unsigned char DAT_18064cdb0[16] = { 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0 };


void LooksLikeSha1_1801695b1(byte* data, uint len, SHA1_buf* buffer)

{
    uint uVar1;
    uint uVar2;
    uint uVar3;
    uint uVar4;
    uint uVar6;
    uint uVar7;
    uint uVar8;
    uint uVar9;
    uint uVar10;
    uint uVar11;
    uint uVar12;
    ulonglong uVar13;
    uint uVar14;
    uint uVar15;
    ulonglong uVar16;
    uint uVar17;
    uint uVar18;
    uint uVar19;
    uint uVar20;
    uint uVar21;
    uint uVar22;
    uint uVar23;
    uint uVar24;
    uint uVar25;
    uint uVar26;
    uint uVar27;
    uint uVar28;
    uint uVar29;
    uint uVar30;
    uint uVar31;
    uint uVar32;
    int iVar33;
    int iVar34;
    int iVar35;
    int iVar36;
    uint local_128;
    uint local_124;
    uint local_120;
    uint local_11c;
    uint local_118;
    uint local_114;
    uint local_110;
    uint local_10c;
    uint local_108;
    uint local_104;
    uint local_100;
    uint local_fc;
    ulonglong local_f8;
    uint local_ec;
    ulonglong local_e8;
    uint local_e0;
    uint local_dc;
    byte* local_d8;
    uint local_d0;
    uint local_cc;
    ulonglong local_c8;
    ulonglong local_c0;
    ulonglong local_b8;
    ulonglong local_b0;
    byte local_a8[18];
    reg16 xmm0, xmm1, xmm2,    xmm6, xmm7, xmm8;

    local_ec = len;
    if (buffer->flag == '\0') {
        uVar15 = -*(int*)&buffer->offs & 0x3f;
        if (len <= uVar15) {
            uVar15 = len;
        }
        Insha1_1_18016aceb(data, uVar15, buffer);
        local_ec = len - uVar15;
        if (local_ec == 0) goto LAB_18016aca5;
        data = data + uVar15;
        buffer->flag = '\x01';
        ConstUser_18016b077(0x12000004b51, buffer->encoded1, buffer->encoded1, local_a8);
        *(short*)&local_a8[16] = *(short*)&local_a8[16] & 0x3ff;
        uint tst = 0;
        for (int i = 2; i < 18; i++)
        {
            tst += local_a8[i] << ((i - 2) * 2);
        }
        memcpy(xmm0.data, DAT_18053c6c0, 16);
        memset(xmm1.data, 0, 16);
        memset(xmm2.data, 0, 16);
        memcpy(xmm8.data, DAT_18064cd50, 16);
        memcpy(xmm7.data, DAT_18064cda0, 16);
        memcpy(xmm6.data, DAT_18064cdb0, 16);

        buffer->hash1 =tst;
        ConstUser_18016b077(0x12000033f37, buffer->encoded2, buffer->encoded2, local_a8);
        *(short*)&local_a8[16] = *(short*)&local_a8[16] & 0x3ff;
        tst = 0;
        for (int i = 2; i < 18; i++)
        {
            tst += local_a8[i] << ((i - 2) * 2);
        }
      
    
          buffer->hash2 =tst;
        ConstUser_18016b077(0x1200001c175, buffer->encoded3, buffer->encoded3, local_a8);
        *(short*)&local_a8[16] = *(short*)&local_a8[16] & 0x3ff;
        tst = 0;
        for (int i = 2; i < 18; i++)
        {
            tst += local_a8[i] << ((i - 2) * 2);
        }

        buffer->hash3 = tst;
        ConstUser_18016b077(0x1200001b218, buffer->encoded4, buffer->encoded4, local_a8);
        *(short*)&local_a8[16] = *(short*)&local_a8[16] & 0x3ff;
        tst = 0;
        for (int i = 2; i < 18; i++)
        {
            tst += local_a8[i] << ((i - 2) * 2);
        }

        buffer->hash4 = tst;
        ConstUser_18016b077(0x12000028292, buffer->encoded5, buffer->encoded5, local_a8);
        *(short*)&local_a8[16] = *(short*)&local_a8[16] & 0x3ff;
        tst = 0;
        for (int i = 2; i < 18; i++)
        {
            tst += local_a8[i] << ((i - 2) * 2);
        }
      
        buffer->hash5 = tst;
    }
    if (local_ec != 0) {
        iVar33 = buffer->prehash;
        do {
            uVar15 = 0x40U - iVar33;
            if (local_ec < 0x40U - iVar33) {
                uVar15 = local_ec;
            }
            if (uVar15 == 0) {
                uVar16 = 0;
            }
            else {
                uVar16 = (ulonglong)uVar15;
                uVar13 = 0;
                do {
                    *(byte*)((longlong)buffer->workspace + (uint)(iVar33 + (int)uVar13)) =
                        data[uVar13];
                    uVar13 = uVar13 + 1;
                    iVar33 = buffer->prehash;
                } while (uVar16 != uVar13);
            }
            local_ec = local_ec - uVar15;
            iVar33 = iVar33 + uVar15;
            buffer->prehash = iVar33;
            if (iVar33 == 0x40) {
                uVar15 = buffer->workspace[0];
                uVar1 = buffer->workspace[1];
                uVar6 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18;
                uVar4 = uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 | uVar1 << 0x18;
                uVar15 = buffer->workspace[2];
                uVar7 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18;
                uVar15 = buffer->workspace[3];
                uVar14 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                local_d0 = buffer->hash1;
                uVar1 = buffer->hash2;
                local_b8 = (ulonglong)uVar1;
                uVar2 = buffer->hash3;
                local_c8 = (ulonglong)uVar2;
                uVar3 = buffer->hash4;
                local_c0 = (ulonglong)uVar3;
                local_cc = buffer->hash5;
                uVar15 = (local_d0 << 5 | local_d0 >> 0x1b) + uVar6 + local_cc +
                    ((uVar3 ^ uVar2) & uVar1 ^ uVar3) + 0x5a827999;
                uVar26 = uVar1 << 0x1e | uVar1 >> 2;
                uVar22 = local_d0 << 0x1e | local_d0 >> 2;
                uVar8 = uVar4 + uVar3 + ((uVar26 ^ uVar2) & local_d0 ^ uVar2) +
                    (uVar15 * 0x20 | uVar15 >> 0x1b) + 0x5a827999;
                uVar17 = uVar7 + uVar2 + ((uVar26 ^ uVar22) & uVar15 ^ uVar26) +
                    (uVar8 * 0x20 | uVar8 >> 0x1b) + 0x5a827999;
                uVar19 = uVar15 * 0x40000000 | uVar15 >> 2;
                uVar15 = buffer->workspace[4];
                uVar10 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar9 = uVar8 * 0x40000000 | uVar8 >> 2;
                uVar27 = uVar26 + uVar14 + ((uVar19 ^ uVar22) & uVar8 ^ uVar22) +
                    (uVar17 * 0x20 | uVar17 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[5];
                uVar11 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar26 = uVar22 + uVar10 + ((uVar9 ^ uVar19) & uVar17 ^ uVar19) +
                    (uVar27 * 0x20 | uVar27 >> 0x1b) + 0x5a827999;
                uVar17 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar15 = buffer->workspace[6];
                uVar8 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18;
                uVar28 = uVar27 * 0x40000000 | uVar27 >> 2;
                uVar22 = uVar19 + uVar11 + ((uVar17 ^ uVar9) & uVar27 ^ uVar9) +
                    (uVar26 * 0x20 | uVar26 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[7];
                uVar12 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar23 = uVar26 * 0x40000000 | uVar26 >> 2;
                uVar19 = uVar9 + uVar8 + ((uVar28 ^ uVar17) & uVar26 ^ uVar17) +
                    (uVar22 * 0x20 | uVar22 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[8];
                uVar9 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18;
                uVar20 = uVar22 * 0x40000000 | uVar22 >> 2;
                uVar26 = uVar17 + uVar12 + ((uVar23 ^ uVar28) & uVar22 ^ uVar28) +
                    (uVar19 * 0x20 | uVar19 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[9];
                uVar17 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar28 = uVar28 + uVar9 + ((uVar20 ^ uVar23) & uVar19 ^ uVar23) +
                    (uVar26 * 0x20 | uVar26 >> 0x1b) + 0x5a827999;
                uVar22 = uVar19 * 0x40000000 | uVar19 >> 2;
                uVar15 = buffer->workspace[10];
                uVar19 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar27 = uVar26 * 0x40000000 | uVar26 >> 2;
                uVar26 = uVar23 + uVar17 + ((uVar22 ^ uVar20) & uVar26 ^ uVar20) +
                    (uVar28 * 0x20 | uVar28 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[0xb];
                uVar23 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar29 = uVar28 * 0x40000000 | uVar28 >> 2;
                uVar28 = uVar20 + uVar19 + ((uVar27 ^ uVar22) & uVar28 ^ uVar22) +
                    (uVar26 * 0x20 | uVar26 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[0xc];
                uVar20 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar24 = uVar26 * 0x40000000 | uVar26 >> 2;
                uVar26 = uVar22 + uVar23 + ((uVar29 ^ uVar27) & uVar26 ^ uVar27) +
                    (uVar28 * 0x20 | uVar28 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[0xd];
                uVar22 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar18 = uVar27 + uVar20 + ((uVar24 ^ uVar29) & uVar28 ^ uVar29) +
                    (uVar26 * 0x20 | uVar26 >> 0x1b) + 0x5a827999;
                uVar21 = uVar28 * 0x40000000 | uVar28 >> 2;
                uVar15 = buffer->workspace[0xe];
                uVar28 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar27 = uVar26 * 0x40000000 | uVar26 >> 2;
                uVar30 = uVar29 + uVar22 + ((uVar21 ^ uVar24) & uVar26 ^ uVar24) +
                    (uVar18 * 0x20 | uVar18 >> 0x1b) + 0x5a827999;
                uVar15 = buffer->workspace[0xf];
                uVar26 = uVar15 >> 0x18 | (uVar15 & 0xff0000) >> 8 | (uVar15 & 0xff00) << 8 | uVar15 << 0x18
                    ;
                uVar29 = uVar18 * 0x40000000 | uVar18 >> 2;
                uVar25 = uVar24 + uVar28 + ((uVar27 ^ uVar21) & uVar18 ^ uVar21) +
                    (uVar30 * 0x20 | uVar30 >> 0x1b) + 0x5a827999;
                uVar31 = uVar30 * 0x40000000 | uVar30 >> 2;
                uVar15 = uVar9 ^ uVar22 ^ uVar6 ^ uVar7;
                uVar24 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar6 = uVar21 + uVar26 + ((uVar29 ^ uVar27) & uVar30 ^ uVar27) +
                    (uVar25 * 0x20 | uVar25 >> 0x1b) + 0x5a827999;
                uVar30 = uVar25 * 0x40000000 | uVar25 >> 2;
                uVar15 = uVar17 ^ uVar28 ^ uVar4 ^ uVar14;
                uVar18 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar15 = uVar27 + uVar24 + ((uVar31 ^ uVar29) & uVar25 ^ uVar29) +
                    (uVar6 * 0x20 | uVar6 >> 0x1b) + 0x5a827999;
                uVar21 = uVar6 * 0x40000000 | uVar6 >> 2;
                uVar4 = uVar19 ^ uVar26 ^ uVar7 ^ uVar10;
                uVar27 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar29 = uVar29 + uVar18 + ((uVar30 ^ uVar31) & uVar6 ^ uVar31) +
                    (uVar15 * 0x20 | uVar15 >> 0x1b) + 0x5a827999;
                uVar4 = uVar15 * 0x40000000 | uVar15 >> 2;
                uVar6 = uVar14 ^ uVar11 ^ uVar23 ^ uVar24;
                uVar7 = uVar6 << 1 | (uint)((int)uVar6 < 0);
                uVar31 = uVar31 + uVar27 + ((uVar21 ^ uVar30) & uVar15 ^ uVar30) +
                    (uVar29 * 0x20 | uVar29 >> 0x1b) + 0x5a827999;
                uVar6 = uVar29 * 0x40000000 | uVar29 >> 2;
                uVar15 = uVar10 ^ uVar8 ^ uVar20 ^ uVar18;
                uVar14 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar25 = uVar30 + uVar7 + ((uVar4 ^ uVar21) & uVar29 ^ uVar21) +
                    (uVar31 * 0x20 | uVar31 >> 0x1b) + 0x5a827999;
                uVar29 = uVar21 + uVar14 + (uVar6 ^ uVar4 ^ uVar31) + (uVar25 * 0x20 | uVar25 >> 0x1b) +
                    0x6ed9eba1;
                uVar31 = uVar31 * 0x40000000 | uVar31 >> 2;
                uVar15 = uVar11 ^ uVar12 ^ uVar22 ^ uVar27;
                uVar15 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar11 = uVar25 * 0x40000000 | uVar25 >> 2;
                uVar8 = uVar8 ^ uVar9 ^ uVar28 ^ uVar7;
                uVar10 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar4 = uVar4 + uVar15 + (uVar31 ^ uVar6 ^ uVar25) + (uVar29 * 0x20 | uVar29 >> 0x1b) +
                    0x6ed9eba1;
                uVar21 = uVar29 * 0x40000000 | uVar29 >> 2;
                uVar8 = uVar12 ^ uVar17 ^ uVar26 ^ uVar14;
                uVar25 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar6 = uVar6 + uVar10 + (uVar11 ^ uVar31 ^ uVar29) + (uVar4 * 0x20 | uVar4 >> 0x1b) +
                    0x6ed9eba1;
                uVar8 = uVar4 * 0x40000000 | uVar4 >> 2;
                uVar9 = uVar9 ^ uVar19 ^ uVar24 ^ uVar15;
                uVar30 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar31 = uVar31 + uVar25 + (uVar21 ^ uVar11 ^ uVar4) + (uVar6 * 0x20 | uVar6 >> 0x1b) +
                    0x6ed9eba1;
                uVar12 = uVar11 + uVar30 + (uVar8 ^ uVar21 ^ uVar6) + (uVar31 * 0x20 | uVar31 >> 0x1b) +
                    0x6ed9eba1;
                uVar11 = uVar6 * 0x40000000 | uVar6 >> 2;
                uVar4 = uVar17 ^ uVar23 ^ uVar18 ^ uVar10;
                uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar32 = uVar31 * 0x40000000 | uVar31 >> 2;
                uVar9 = uVar19 ^ uVar20 ^ uVar27 ^ uVar25;
                uVar29 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar17 = uVar21 + uVar4 + (uVar11 ^ uVar8 ^ uVar31) + (uVar12 * 0x20 | uVar12 >> 0x1b) +
                    0x6ed9eba1;
                uVar31 = uVar12 * 0x40000000 | uVar12 >> 2;
                uVar9 = uVar23 ^ uVar22 ^ uVar7 ^ uVar30;
                uVar6 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar8 = uVar8 + uVar29 + (uVar32 ^ uVar11 ^ uVar12) + (uVar17 * 0x20 | uVar17 >> 0x1b) +
                    0x6ed9eba1;
                uVar21 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar9 = uVar20 ^ uVar28 ^ uVar14 ^ uVar4;
                uVar12 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar9 = uVar11 + uVar6 + (uVar31 ^ uVar32 ^ uVar17) + (uVar8 * 0x20 | uVar8 >> 0x1b) +
                    0x6ed9eba1;
                uVar20 = uVar32 + uVar12 + (uVar21 ^ uVar31 ^ uVar8) + (uVar9 * 0x20 | uVar9 >> 0x1b) +
                    0x6ed9eba1;
                uVar17 = uVar8 * 0x40000000 | uVar8 >> 2;
                uVar8 = uVar22 ^ uVar26 ^ uVar15 ^ uVar29;
                local_e0 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar19 = uVar9 * 0x40000000 | uVar9 >> 2;
                uVar8 = uVar28 ^ uVar24 ^ uVar10 ^ uVar6;
                uVar23 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar11 = uVar31 + local_e0 + (uVar17 ^ uVar21 ^ uVar9) + (uVar20 * 0x20 | uVar20 >> 0x1b) +
                    0x6ed9eba1;
                uVar31 = uVar20 * 0x40000000 | uVar20 >> 2;
                uVar8 = uVar26 ^ uVar18 ^ uVar25 ^ uVar12;
                uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar22 = uVar21 + uVar23 + (uVar19 ^ uVar17 ^ uVar20) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0x6ed9eba1;
                uVar20 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar9 = uVar24 ^ uVar27 ^ uVar30 ^ local_e0;
                uVar9 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar17 = uVar17 + uVar8 + (uVar31 ^ uVar19 ^ uVar11) + (uVar22 * 0x20 | uVar22 >> 0x1b) +
                    0x6ed9eba1;
                uVar11 = uVar19 + uVar9 + (uVar20 ^ uVar31 ^ uVar22) + (uVar17 * 0x20 | uVar17 >> 0x1b) +
                    0x6ed9eba1;
                uVar28 = uVar22 * 0x40000000 | uVar22 >> 2;
                uVar19 = uVar18 ^ uVar7 ^ uVar4 ^ uVar23;
                local_dc = uVar19 << 1 | (uint)((int)uVar19 < 0);
                uVar19 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar22 = uVar27 ^ uVar14 ^ uVar29 ^ uVar8;
                uVar26 = uVar22 << 1 | (uint)((int)uVar22 < 0);
                uVar18 = uVar31 + local_dc + (uVar28 ^ uVar20 ^ uVar17) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0x6ed9eba1;
                uVar22 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar17 = uVar7 ^ uVar15 ^ uVar6 ^ uVar9;
                uVar27 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar11 = uVar20 + uVar26 + (uVar19 ^ uVar28 ^ uVar11) + (uVar18 * 0x20 | uVar18 >> 0x1b) +
                    0x6ed9eba1;
                uVar21 = uVar18 * 0x40000000 | uVar18 >> 2;
                uVar17 = uVar14 ^ uVar10 ^ uVar12 ^ local_dc;
                uVar20 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar7 = uVar28 + uVar27 + (uVar22 ^ uVar19 ^ uVar18) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0x6ed9eba1;
                uVar17 = uVar19 + uVar20 + (uVar21 ^ uVar22 ^ uVar11) + (uVar7 * 0x20 | uVar7 >> 0x1b) +
                    0x6ed9eba1;
                uVar28 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar15 = uVar15 ^ uVar25 ^ local_e0 ^ uVar26;
                uVar24 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar11 = uVar7 * 0x40000000 | uVar7 >> 2;
                uVar15 = uVar10 ^ uVar30 ^ uVar23 ^ uVar27;
                uVar10 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar7 = uVar22 + uVar24 + (uVar28 ^ uVar21 ^ uVar7) + (uVar17 * 0x20 | uVar17 >> 0x1b) +
                    0x6ed9eba1;
                uVar19 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar15 = uVar25 ^ uVar4 ^ uVar8 ^ uVar20;
                uVar22 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar18 = uVar21 + uVar10 + (uVar11 ^ uVar28 ^ uVar17) + (uVar7 * 0x20 | uVar7 >> 0x1b) +
                    0x6ed9eba1;
                uVar17 = uVar7 * 0x40000000 | uVar7 >> 2;
                uVar15 = uVar30 ^ uVar29 ^ uVar9 ^ uVar24;
                uVar15 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar28 = uVar28 + uVar22 + (uVar19 ^ uVar11 ^ uVar7) + (uVar18 * 0x20 | uVar18 >> 0x1b) +
                    0x6ed9eba1;
                iVar34 = uVar11 + uVar15 + ((uVar18 | uVar17) & uVar19 | uVar18 & uVar17) +
                    (uVar28 * 0x20 | uVar28 >> 0x1b);
                uVar21 = uVar18 * 0x40000000 | uVar18 >> 2;
                uVar7 = iVar34 + 0x8f1bbcdc;
                uVar4 = uVar4 ^ uVar6 ^ local_dc ^ uVar10;
                uVar11 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                iVar33 = uVar19 + uVar11 + ((uVar28 | uVar21) & uVar17 | uVar28 & uVar21) +
                    (uVar7 * 0x20 | uVar7 >> 0x1b);
                uVar14 = uVar28 * 0x40000000 | uVar28 >> 2;
                uVar4 = uVar29 ^ uVar12 ^ uVar26 ^ uVar22;
                uVar28 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar4 = iVar33 + 0x8f1bbcdc;
                uVar18 = iVar34 * 0x40000000 | uVar7 >> 2;
                iVar34 = uVar17 + uVar28 + ((uVar7 | uVar14) & uVar21 | uVar7 & uVar14) +
                    (uVar4 * 0x20 | uVar4 >> 0x1b);
                uVar17 = uVar6 ^ local_e0 ^ uVar27 ^ uVar15;
                uVar19 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar6 = iVar34 + 0x8f1bbcdc;
                iVar36 = uVar21 + uVar19 + ((uVar4 | uVar18) & uVar14 | uVar4 & uVar18) +
                    (uVar6 * 0x20 | uVar6 >> 0x1b);
                uVar17 = iVar33 * 0x40000000 | uVar4 >> 2;
                uVar4 = uVar12 ^ uVar23 ^ uVar20 ^ uVar11;
                uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar29 = iVar36 + 0x8f1bbcdc;
                iVar33 = uVar14 + uVar4 + ((uVar6 | uVar17) & uVar18 | uVar6 & uVar17) +
                    (uVar29 * 0x20 | uVar29 >> 0x1b);
                uVar12 = iVar34 * 0x40000000 | uVar6 >> 2;
                uVar7 = iVar33 + 0x8f1bbcdc;
                uVar6 = local_e0 ^ uVar8 ^ uVar24 ^ uVar28;
                uVar21 = uVar6 << 1 | (uint)((int)uVar6 < 0);
                iVar35 = uVar18 + uVar21 + ((uVar29 | uVar12) & uVar17 | uVar29 & uVar12) +
                    (uVar7 * 0x20 | uVar7 >> 0x1b);
                uVar14 = iVar36 * 0x40000000 | uVar29 >> 2;
                uVar6 = uVar23 ^ uVar9 ^ uVar10 ^ uVar19;
                uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
                uVar23 = iVar35 + 0x8f1bbcdc;
                uVar18 = iVar33 * 0x40000000 | uVar7 >> 2;
                iVar33 = uVar17 + uVar6 + ((uVar7 | uVar14) & uVar12 | uVar7 & uVar14) +
                    (uVar23 * 0x20 | uVar23 >> 0x1b);
                uVar8 = uVar8 ^ local_dc ^ uVar22 ^ uVar4;
                uVar7 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar17 = iVar33 + 0x8f1bbcdc;
                iVar34 = uVar12 + uVar7 + ((uVar23 | uVar18) & uVar14 | uVar23 & uVar18) +
                    (uVar17 * 0x20 | uVar17 >> 0x1b);
                uVar29 = iVar35 * 0x40000000 | uVar23 >> 2;
                uVar8 = uVar9 ^ uVar26 ^ uVar15 ^ uVar21;
                uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar12 = iVar34 + 0x8f1bbcdc;
                iVar35 = uVar14 + uVar8 + ((uVar17 | uVar29) & uVar18 | uVar17 & uVar29) +
                    (uVar12 * 0x20 | uVar12 >> 0x1b);
                uVar9 = iVar33 * 0x40000000 | uVar17 >> 2;
                uVar25 = iVar35 + 0x8f1bbcdc;
                uVar17 = local_dc ^ uVar27 ^ uVar11 ^ uVar6;
                uVar14 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                iVar36 = uVar18 + uVar14 + ((uVar12 | uVar9) & uVar29 | uVar12 & uVar9) +
                    (uVar25 * 0x20 | uVar25 >> 0x1b);
                uVar18 = iVar34 * 0x40000000 | uVar12 >> 2;
                uVar17 = uVar26 ^ uVar20 ^ uVar28 ^ uVar7;
                uVar23 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar12 = iVar36 + 0x8f1bbcdc;
                uVar30 = iVar35 * 0x40000000 | uVar25 >> 2;
                iVar35 = uVar29 + uVar23 + ((uVar25 | uVar18) & uVar9 | uVar25 & uVar18) +
                    (uVar12 * 0x20 | uVar12 >> 0x1b);
                uVar17 = uVar27 ^ uVar24 ^ uVar19 ^ uVar8;
                uVar26 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar17 = iVar35 + 0x8f1bbcdc;
                iVar33 = uVar9 + uVar26 + ((uVar12 | uVar30) & uVar18 | uVar12 & uVar30) +
                    (uVar17 * 0x20 | uVar17 >> 0x1b);
                uVar25 = iVar36 * 0x40000000 | uVar12 >> 2;
                uVar9 = uVar20 ^ uVar10 ^ uVar4 ^ uVar14;
                uVar12 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar9 = iVar33 + 0x8f1bbcdc;
                iVar34 = uVar18 + uVar12 + ((uVar17 | uVar25) & uVar30 | uVar17 & uVar25) +
                    (uVar9 * 0x20 | uVar9 >> 0x1b);
                uVar29 = iVar35 * 0x40000000 | uVar17 >> 2;
                uVar20 = iVar34 + 0x8f1bbcdc;
                uVar17 = uVar24 ^ uVar22 ^ uVar21 ^ uVar23;
                uVar27 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                iVar36 = uVar30 + uVar27 + ((uVar9 | uVar29) & uVar25 | uVar9 & uVar29) +
                    (uVar20 * 0x20 | uVar20 >> 0x1b);
                uVar9 = iVar33 * 0x40000000 | uVar9 >> 2;
                uVar17 = uVar10 ^ uVar15 ^ uVar6 ^ uVar26;
                uVar10 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar24 = iVar36 + 0x8f1bbcdc;
                uVar18 = iVar34 * 0x40000000 | uVar20 >> 2;
                iVar34 = uVar25 + uVar10 + ((uVar20 | uVar9) & uVar29 | uVar20 & uVar9) +
                    (uVar24 * 0x20 | uVar24 >> 0x1b);
                uVar17 = uVar22 ^ uVar11 ^ uVar7 ^ uVar12;
                uVar20 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar17 = iVar34 + 0x8f1bbcdc;
                iVar35 = uVar29 + uVar20 + ((uVar24 | uVar18) & uVar9 | uVar24 & uVar18) +
                    (uVar17 * 0x20 | uVar17 >> 0x1b);
                uVar24 = iVar36 * 0x40000000 | uVar24 >> 2;
                uVar15 = uVar15 ^ uVar28 ^ uVar8 ^ uVar27;
                uVar15 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar22 = iVar35 + 0x8f1bbcdc;
                iVar33 = uVar9 + uVar15 + ((uVar17 | uVar24) & uVar18 | uVar17 & uVar24) +
                    (uVar22 * 0x20 | uVar22 >> 0x1b);
                uVar29 = iVar34 * 0x40000000 | uVar17 >> 2;
                uVar9 = iVar33 + 0x8f1bbcdc;
                uVar17 = uVar11 ^ uVar19 ^ uVar14 ^ uVar10;
                local_fc = uVar17 << 1 | (uint)((int)uVar17 < 0);
                iVar34 = uVar18 + local_fc + ((uVar22 | uVar29) & uVar24 | uVar22 & uVar29) +
                    (uVar9 * 0x20 | uVar9 >> 0x1b);
                uVar11 = iVar35 * 0x40000000 | uVar22 >> 2;
                uVar17 = uVar28 ^ uVar4 ^ uVar23 ^ uVar20;
                local_104 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar22 = iVar34 + 0x8f1bbcdc;
                uVar17 = iVar33 * 0x40000000 | uVar9 >> 2;
                iVar35 = uVar24 + local_104 + ((uVar9 | uVar11) & uVar29 | uVar9 & uVar11) +
                    (uVar22 * 0x20 | uVar22 >> 0x1b);
                uVar9 = uVar19 ^ uVar21 ^ uVar26 ^ uVar15;
                local_100 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar28 = iVar35 + 0x8f1bbcdc;
                iVar33 = uVar29 + local_100 + ((uVar22 | uVar17) & uVar11 | uVar22 & uVar17) +
                    (uVar28 * 0x20 | uVar28 >> 0x1b);
                uVar19 = iVar34 * 0x40000000 | uVar22 >> 2;
                uVar4 = uVar4 ^ uVar6 ^ uVar12 ^ local_fc;
                uVar22 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar9 = iVar33 + 0x8f1bbcdc;
                uVar11 = uVar11 + uVar22 + (uVar19 ^ uVar17 ^ uVar28) + (uVar9 * 0x20 | uVar9 >> 0x1b) +
                    0xca62c1d6;
                uVar24 = iVar35 * 0x40000000 | uVar28 >> 2;
                uVar4 = uVar21 ^ uVar7 ^ uVar27 ^ local_104;
                uVar18 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar29 = iVar33 * 0x40000000 | uVar9 >> 2;
                uVar4 = uVar6 ^ uVar8 ^ uVar10 ^ local_100;
                local_11c = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar9 = uVar17 + uVar18 + (uVar24 ^ uVar19 ^ uVar9) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0xca62c1d6;
                uVar28 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar4 = uVar7 ^ uVar14 ^ uVar20 ^ uVar22;
                local_108 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                uVar19 = uVar19 + local_11c + (uVar29 ^ uVar24 ^ uVar11) + (uVar9 * 0x20 | uVar9 >> 0x1b) +
                    0xca62c1d6;
                uVar17 = uVar9 * 0x40000000 | uVar9 >> 2;
                uVar4 = uVar8 ^ uVar23 ^ uVar15 ^ uVar18;
                uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
                local_f8 = (ulonglong)uVar4;
                uVar11 = uVar24 + local_108 + (uVar28 ^ uVar29 ^ uVar9) + (uVar19 * 0x20 | uVar19 >> 0x1b) +
                    0xca62c1d6;
                uVar9 = uVar29 + uVar4 + (uVar17 ^ uVar28 ^ uVar19) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0xca62c1d6;
                uVar6 = uVar19 * 0x40000000 | uVar19 >> 2;
                uVar8 = uVar14 ^ uVar26 ^ local_fc ^ local_11c;
                uVar7 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar14 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar8 = uVar23 ^ uVar12 ^ local_104 ^ local_108;
                uVar19 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                local_e8 = (ulonglong)uVar19;
                uVar11 = uVar28 + uVar7 + (uVar6 ^ uVar17 ^ uVar11) + (uVar9 * 0x20 | uVar9 >> 0x1b) +
                    0xca62c1d6;
                uVar23 = uVar9 * 0x40000000 | uVar9 >> 2;
                uVar8 = uVar26 ^ uVar27 ^ local_100 ^ uVar4;
                local_10c = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar8 = uVar17 + uVar19 + (uVar14 ^ uVar6 ^ uVar9) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0xca62c1d6;
                uVar26 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar9 = uVar12 ^ uVar10 ^ uVar22 ^ uVar7;
                local_118 = uVar9 << 1 | (uint)((int)uVar9 < 0);
                uVar17 = uVar6 + local_10c + (uVar23 ^ uVar14 ^ uVar11) + (uVar8 * 0x20 | uVar8 >> 0x1b) +
                    0xca62c1d6;
                uVar11 = uVar14 + local_118 + (uVar26 ^ uVar23 ^ uVar8) + (uVar17 * 0x20 | uVar17 >> 0x1b) +
                    0xca62c1d6;
                uVar9 = uVar8 * 0x40000000 | uVar8 >> 2;
                uVar8 = uVar27 ^ uVar20 ^ uVar18 ^ uVar19;
                local_124 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar6 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar8 = uVar10 ^ uVar15 ^ local_11c ^ local_10c;
                local_110 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar27 = uVar23 + local_124 + (uVar9 ^ uVar26 ^ uVar17) + (uVar11 * 0x20 | uVar11 >> 0x1b) +
                    0xca62c1d6;
                uVar12 = uVar11 * 0x40000000 | uVar11 >> 2;
                uVar8 = uVar20 ^ local_fc ^ local_108 ^ local_118;
                local_114 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar17 = uVar26 + local_110 + (uVar6 ^ uVar9 ^ uVar11) + (uVar27 * 0x20 | uVar27 >> 0x1b) +
                    0xca62c1d6;
                uVar10 = uVar27 * 0x40000000 | uVar27 >> 2;
                uVar15 = uVar15 ^ local_104 ^ uVar4 ^ local_124;
                local_128 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar8 = uVar9 + local_114 + (uVar12 ^ uVar6 ^ uVar27) + (uVar17 * 0x20 | uVar17 >> 0x1b) +
                    0xca62c1d6;
                uVar6 = uVar6 + local_128 + (uVar10 ^ uVar12 ^ uVar17) + (uVar8 * 0x20 | uVar8 >> 0x1b) +
                    0xca62c1d6;
                uVar26 = uVar17 * 0x40000000 | uVar17 >> 2;
                uVar15 = local_fc ^ local_100 ^ uVar7 ^ local_110;
                uVar15 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar9 = uVar8 * 0x40000000 | uVar8 >> 2;
                uVar17 = local_104 ^ uVar22 ^ uVar19 ^ local_114;
                uVar17 = uVar17 << 1 | (uint)((int)uVar17 < 0);
                uVar27 = uVar12 + uVar15 + (uVar26 ^ uVar10 ^ uVar8) + (uVar6 * 0x20 | uVar6 >> 0x1b) +
                    0xca62c1d6;
                uVar8 = local_100 ^ uVar18 ^ local_10c ^ local_128;
                uVar19 = uVar6 * 0x40000000 | uVar6 >> 2;
                uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
                uVar6 = uVar10 + uVar17 + (uVar9 ^ uVar26 ^ uVar6) + (uVar27 * 0x20 | uVar27 >> 0x1b) +
                    0xca62c1d6;
                uVar10 = uVar27 * 0x40000000 | uVar27 >> 2;
                uVar15 = uVar22 ^ local_11c ^ local_118 ^ uVar15;
                local_120 = uVar15 << 1 | (uint)((int)uVar15 < 0);
                uVar22 = uVar26 + uVar8 + (uVar19 ^ uVar9 ^ uVar27) + (uVar6 * 0x20 | uVar6 >> 0x1b) +
                    0xca62c1d6;
                uVar17 = uVar18 ^ local_108 ^ local_124 ^ uVar17;
                uVar15 = uVar9 + local_120 + (uVar10 ^ uVar19 ^ uVar6) + (uVar22 * 0x20 | uVar22 >> 0x1b) +
                    0xca62c1d6;
                uVar6 = uVar6 * 0x40000000 | uVar6 >> 2;
                uVar8 = uVar4 ^ local_11c ^ local_110 ^ uVar8;
                uVar17 = (uVar17 << 1 | (uint)((int)uVar17 < 0)) + uVar19 + (uVar6 ^ uVar10 ^ uVar22) +
                    (uVar15 * 0x20 | uVar15 >> 0x1b) + 0xca62c1d6;
                uVar9 = uVar22 * 0x40000000 | uVar22 >> 2;
                iVar33 = (uVar8 << 1 | (uint)((int)uVar8 < 0)) + uVar10 + (uVar9 ^ uVar6 ^ uVar15) +
                    (uVar17 * 0x20 | uVar17 >> 0x1b);
                uVar8 = uVar7 ^ local_108 ^ local_114 ^ local_120;
                uVar4 = uVar15 * 0x40000000 | uVar15 >> 2;
                uVar15 = iVar33 + 0xca62c1d6;
                buffer->hash1 =
                    (uVar8 << 1 | (uint)((int)uVar8 < 0)) + local_d0 + uVar6 + (uVar4 ^ uVar9 ^ uVar17) +
                    (uVar15 * 0x20 | uVar15 >> 0x1b) + 0xca62c1d6;
                buffer->hash2 = uVar1 + iVar33 + 0xca62c1d6;
                buffer->hash3 = (uVar17 * 0x40000000 | uVar17 >> 2) + uVar2;
                buffer->hash4 = uVar4 + uVar3;
                buffer->hash5 = uVar9 + local_cc;
                buffer->offs = buffer->offs + 0x40;
                buffer->prehash = 0;
                iVar33 = 0;
                local_d8 = data;
                local_b0 = uVar16;
            }
            data = data + uVar16;
        } while (local_ec != 0);
    }
LAB_18016aca5:
    return;
}

/// (0x)00 00 00 00 00 00 00 00 || mHash||salt

void Shabuf_Transform_18016b9ac(uint* param_1, SHA1_buf* buffer)

{
    uint uVar1;
    longlong lVar42;
    byte* output;
    uint uVar45;
    byte* pbVar46;
    ulonglong uVar47;
    uint* local_200;
    byte local_1f8[82];
    byte local_198[66];
    byte local_148[34];
    byte local_118[82];
    
    Encode_Buffer_Const_18016b14f(buffer);
  
    uVar45 = *(uint*)&buffer->offs & 0xf;
    local_200 = param_1;
    if (uVar45 == 0) {
        uVar1 = buffer->counter;
        PFUN_180119595((uint*)DAT_18090a3d0, (uint*)DAT_1812f1614, 0x11, 0x156da023);
        PFUN_180119595((uint*)DAT_18090a3d0, (uint*)DAT_1812f1614, 0x11, 0x156da023);
        uVar47 = 0x420000328c7;
        output = DAT_1812f1614;
        pbVar46 = DAT_1812f1614;
    }
    else {
        output = local_118;
        lVar42 = (ulonglong)(uVar45 ^ 0xf) * 0x42;
        ConstUser_18016b077(0x4200002960f, (byte*)buffer->encbytes[buffer->counter],
            DAT_180909fa0 + lVar42, output);
        uVar1 = buffer->counter;
        pbVar46 = DAT_18090a420 + lVar42;
        uVar47 = 0x420000364b3;
    }
    ConstUser_18016b077(uVar47, output, pbVar46, (byte*)buffer->encbytes[uVar1]);
    if ((7 < uVar45) || (buffer->counter < 3)) {
        uVar45 = buffer->counter + 1;
        buffer->counter = uVar45;
        if (uVar45 == 4) {
            Insha1_3_18019ba88(buffer->encoded1, (byte*)buffer->encbytes);
            buffer->counter = 0;
            uVar45 = 0;
        }
        else {
            if (3 < uVar45) goto LAB_18016bc2b;
        }
        do {
            PFUN_180119595((uint*)DAT_18090a800, (uint*)DAT_1812f165c, 0x11, 0xb9f42cbd);
            PFUN_180119595((uint*)DAT_18090a800, (uint*)DAT_1812f165c, 0x11, 0xb9f42cbd);
            ConstUser_18016b077(0x420000243f2, DAT_1812f165c, DAT_1812f165c,
                (byte*)buffer->encbytes[uVar45]);
            uVar45 = buffer->counter + 1;
            buffer->counter = uVar45;
        } while (uVar45 < 4);
    }
LAB_18016bc2b:
    reg16 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8,xmm9,xmm11,xmm12;

    uVar47 = buffer->offs;
    buffer->offs = uVar47 * 8;
    memset(xmm8.data, 0, 16);
    memset(local_118, 0, 66);
    *(short*)&local_118 = 0x605;
    xmm0.assign8(uVar47);
    xmm0.PSHUFD(xmm0, 0x44);
    xmm0.PSLLQ(0x3);
    memcpy(xmm1.data, xmm0.data,16);
    xmm1.PSRLQ(2);
    memcpy(xmm3.data, xmm0.data, 16);
    xmm3.PUNPCKHQDQ(xmm1);
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(4);
    memcpy(xmm9.data, xmm0.data, 16);
    xmm9.PSRLQ(6);
    *(ulonglong*)xmm9.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(8);
    memcpy(xmm4.data, xmm0.data, 16);
    xmm4.PSRLQ(0xa);
    *(ulonglong*)xmm4.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0xc);
    memcpy(xmm11.data, xmm0.data, 16);
    xmm11.PSRLQ(0xe);
    *(ulonglong*)xmm11.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0x10);
    memcpy(xmm5.data, xmm0.data, 16);
    xmm5.PSRLQ(0x12);
    *(ulonglong*)xmm5.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0x14);
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x16);
    *(ulonglong*)xmm6.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0x18);
    memcpy(xmm2.data, xmm0.data, 16);
    xmm2.PSRLQ(0x1a);
    *(ulonglong*)xmm2.data = *(ulonglong*)xmm1.data;
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0x1c);
    memcpy(xmm7.data, xmm0.data, 16);
    xmm7.PSRLQ(0x1e);
    *(ulonglong*)xmm7.data = *(ulonglong*)xmm1.data;
    {
        unsigned char dt[16] = {0xff,0,0,0,0,0,0,0,0xff,0,0,0,0,0,0,0 };
        memcpy(xmm12.data, dt, 16);
    }
    xmm7.ANDPD(xmm12);
    xmm2.ANDPD(xmm12);
    xmm2.PACKUSWB(xmm7);

    xmm6.ANDPD(xmm12);
    xmm5.ANDPD(xmm12);
    xmm5.PACKUSWB(xmm6);
    xmm5.PACKUSWB(xmm2);

    xmm11.ANDPD(xmm12);
    xmm4.ANDPD(xmm12);
    xmm4.PACKUSWB(xmm11);

    xmm9.ANDPD(xmm12);
    xmm3.ANDPD(xmm12);
    xmm3.PACKUSWB(xmm9);
    xmm3.PACKUSWB(xmm4);
    xmm3.PACKUSWB(xmm5);
    memset(xmm9.data, 3, 16);
    xmm3.PAND(xmm9);
    memcpy(&local_118[2], xmm3.data, 16);
      
    memcpy(xmm2.data, xmm0.data, 16);
    xmm2.PSRLQ(0x20);
    memcpy(xmm3.data, xmm0.data, 16);
    xmm3.PSRLQ(0x22);
    *(ulonglong*)xmm3.data = *(ulonglong*)xmm2.data;
    memcpy(xmm2.data, xmm0.data, 16);
    xmm2.PSRLQ(0x24);
    memcpy(xmm11.data, xmm0.data, 16);
    xmm11.PSRLQ(0x26);
    *(ulonglong*)xmm11.data = *(ulonglong*)xmm2.data;
    memcpy(xmm2.data, xmm0.data, 16);
    xmm2.PSRLQ(0x28);
    memcpy(xmm5.data, xmm0.data, 16);
    xmm5.PSRLQ(0x2a);
    *(ulonglong*)xmm5.data = *(ulonglong*)xmm2.data;
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x2c);
    memcpy(xmm2.data, xmm0.data, 16);
    xmm2.PSRLQ(0x2e);
    *(ulonglong*)xmm2.data = *(ulonglong*)xmm6.data;
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x30);
    memcpy(xmm7.data, xmm0.data, 16);
    xmm7.PSRLQ(0x32);
    *(ulonglong*)xmm7.data = *(ulonglong*)xmm6.data;
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x34);
    memcpy(xmm1.data, xmm0.data, 16);
    xmm1.PSRLQ(0x36);
    *(ulonglong*)xmm1.data = *(ulonglong*)xmm6.data;
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x38);
    memcpy(xmm4.data, xmm0.data, 16);
    xmm4.PSRLQ(0x3a);
    *(ulonglong*)xmm4.data = *(ulonglong*)xmm6.data;
    memcpy(xmm6.data, xmm0.data, 16);
    xmm6.PSRLQ(0x3c);
    memcpy(xmm0.data, xmm0.data, 16);
    xmm0.PSRLQ(0x3e);
    *(ulonglong*)xmm0.data = *(ulonglong*)xmm6.data;
    xmm0.ANDPD(xmm12);
    xmm4.ANDPD(xmm12);
    xmm4.PACKUSWB(xmm0);
    xmm1.ANDPD(xmm12);
    xmm7.ANDPD(xmm12);
    xmm7.PACKUSWB(xmm1);
    xmm7.PACKUSWB(xmm4);
    xmm2.ANDPD(xmm12);
    xmm5.ANDPD(xmm12);
    xmm5.PACKUSWB(xmm2);

    xmm11.ANDPD(xmm12);
    xmm3.ANDPD(xmm12);
    xmm3.PACKUSWB(xmm11);
    xmm3.PACKUSWB(xmm5);
    xmm3.PACKUSWB(xmm7);
    xmm3.PAND(xmm9);
    memcpy(&local_118[18], xmm3.data, 16);
    ConstUser_18016b077(0x42000029ae0, local_118, local_118, local_198);
    ConstUser_18016b077(0x42000002383, local_198, (byte*)buffer->encbytes[3],
        (byte*)buffer->encbytes[3]);
    Insha1_3_18019ba88(buffer->encoded1, (byte*)buffer->encbytes);
    memset(local_118, 0, 34);
    memcpy(&local_118[32], &buffer->encoded4[16], 2);
    memcpy(&local_118[16], buffer->encoded4, 16);
    local_118[15] = 4;
    ConstUser_18016b077(0x400120000318a3, buffer->encoded5, local_118, local_148);
    memset(local_118, 0, 32);
    memcpy(&local_118[48], &buffer->encoded3[16], 2);
    memcpy(&local_118[32], &buffer->encoded3[0], 16);
    local_118[31] = 3;
    ConstUser_18016b077(0x4002200002cdf8, local_148, local_118, local_198);
    memset(local_118, 0, 34);
    memcpy(&local_118[32], &buffer->encoded1[16], 2);
    memcpy(&local_118[16], buffer->encoded1, 16);
    local_118[15] = 3;
    ConstUser_18016b077(0x40012000016c8e, buffer->encoded2, local_118, local_148);
    memcpy(&local_118[64], &local_148[16], 16);
    memcpy(&local_118[48], &local_148[0], 16);
    memcpy(&local_118[80], &local_148[32], 2);
    local_118[47] = 7;
    memset(local_118, 0, 47);
    ConstUser_18016b077(0x8003200000370b, local_198, local_118, local_1f8);
    ConstUser_18016b077(0x52000032c33, local_1f8, local_1f8, (byte*)local_200);
    return;
}
Integer Longstringproc(char *in, size_t len,byte* out)
{
    SHA1_buf buffer;
    Fill_1c8_buffer_18016ae81(&buffer);
    byte local_270[82];
  
    LooksLikeSha1_1801695b1(in, len, &buffer);
    Shabuf_Transform_18016b9ac((uint*)local_270, &buffer);
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