/**
 *  Flic 2 C module
 *
 *  Copyright (C) 2022 Shortcut Labs AB
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "flic2_crypto.h"

union Fe {
    uint32_t v[10];
    uint64_t l[5];
};

struct Precomp {
    union Fe y_p_x, y_m_x, t_2d;
};

static const uint32_t basepoint_mu[9] = {0x0a2c131b,0xed9ce5a3,0x086329a7,0x2106215d,0xffffffeb,0xffffffff,0xffffffff,0xffffffff,0x0000000f};
static const uint32_t basepoint_order[9] = {0x5cf5d3ed,0x5812631a,0xa2f79cd6,0x14def9de,0x00000000,0x00000000,0x00000000,0x10000000,0x00000000};

static const struct Precomp precomp_a[9] = {{{{0x3a4b7f4,0x5dae24,0x1c6caa2,0x1b93456,0x2d97447,0x20a9d2,0x3659776,0xba0b38,0x1eeb722,0x17a26e7}},{{0xd5cbbd,0x134edee,0x3e56030,0x4f0d2f,0x3008fd6,0xb02c07,0x185315d,0xe83262,0x2a55e6c,0x15ed322}},{{0x8a5b7d,0x1f1e244,0x1ec3509,0x1630a5b,0x1e346c9,0xfc4d,0x2e07a4f,0x18fd434,0x31da98c,0x17cd4f9}}},{{{0x1c8d4a1,0x1002eee,0x148d5,0x1fa202a,0x2973c32,0x199f760,0x23415d7,0x1d0dd97,0x1b6760c,0xa8a916}},{{0x3884f40,0xabe42e,0x23dff36,0xee1dec,0x272ee60,0x8f20fe,0x1c3278e,0x1bb6e9f,0x1d70a76,0x1cae74e}},{{0x858259,0x1058af8,0x37fc169,0xa9e726,0x2e4beda,0x4248ab,0x2c9f7bf,0xc7bd57,0xa49ca,0x12e8788}}},{{{0x306c3a9,0x107f87,0x25e3211,0x2d8ce1,0xc0a3e1,0xa52131,0x26ff12e,0x5051c7,0xf30e38,0xf8de29}},{{0x1354c0,0x120fafa,0x3a29777,0x6ec2c9,0xdb2af9,0x1952a57,0x2d16433,0xb1ae8f,0x31c42e,0x182b3b4}},{{0x1051059,0x1787083,0x995057,0x1356a86,0x3ee4fd,0xdbe479,0xfd22f2,0x19175f7,0xa1be1f,0xc8d716}}},{{{0x309299,0x1c2a331,0x106dd70,0xf1dd3,0x3da8924,0x447316,0x293f6c8,0x1536309,0x426a9a,0x1fac2e}},{{0x146a0f3,0x4bcc2c,0x181dcd9,0x1c60fb8,0x2acfc6d,0xddc5b1,0x39ded86,0xb2c8c1,0x3eebfcd,0x15e6ee}},{{0x29ec3f8,0x1f8cb81,0x2375a3f,0xfc9fde,0x22ef98b,0x1b96364,0xccf0c2,0xfd762f,0x2627ed3,0x74a97d}}},{{{0x2de91e,0x81ea1f,0x2f32fe3,0xfb4f2f,0x2228a57,0x589182,0x1d865c1,0xf9933d,0x1976e8c,0x10acefa}},{{0x3de27c,0x147ec66,0x39e0654,0x1a9d726,0x36780b7,0x62a22f,0x20cdc8d,0x25db29,0x233ad89,0x868744}},{{0x22fc598,0x2fac50,0x11f98a7,0x104493e,0x3913fe3,0x50b255,0x21581b5,0x11269c9,0x21867b8,0x1c9fd74}}},{{{0x1133a62,0x1d97895,0x32bf292,0x1eeab9d,0x1bcf64a,0x41aabb,0x16e8dd3,0x1603835,0x510a3,0x15d116e}},{{0x153dcfc,0x98c61a,0x1c0bc2d,0x14f4615,0x5f3e32,0x189f19a,0x6dd490,0x11a7976,0x677729,0x4541e5}},{{0x30801cf,0x69c9c5,0x22c22c,0xd32c92,0x3db31bd,0xa73a3f,0x2d27e6d,0x121524d,0x3c97cb9,0xa782b5}}},{{{0x8b4a2,0x1998f08,0x3a9db9a,0x1276ddc,0xf6d9c1,0x190f2d1,0x1ce7ffe,0x198289e,0x283048,0x13690cf}},{{0x1b8d242,0x13980fe,0x94df84,0x1674fb5,0x27df6fc,0x34420b,0x2ae70e5,0x68f40d,0x1f16cec,0xcd505b}},{{0xa9b2fe,0x1050840,0x3255e0a,0x3d79ba,0x622cce,0xcf8b45,0x64d2e8,0x1889c18,0x62eda4,0x1c4121}}},{{{0x6421a,0x2cfd4d,0x912dee,0x16e3ad0,0x3ac824b,0x37389e,0x3fe5512,0x1227e0d,0x35e1013,0xdf8666}},{{0x116de95,0x717b62,0x3602477,0x1d808da,0x11832d7,0x816ae7,0x21ea44a,0x84f501,0x1a7a7bd,0xb829cd}},{{0xe50830,0x9df515,0x386d3fa,0x1ea8c72,0x3a52eee,0x134b131,0x138d774,0xc0cac2,0x1d3d116,0x1b7a936}}},{{{0x3c4549d,0x1c42c09,0x532759,0x8f4698,0x97e644,0x19d9866,0x2ea59a8,0x1231d81,0x3461d8e,0x1fcd585}},{{0x842af6,0x1e64296,0x2f85f92,0xa4c659,0x177eb2c,0x1b2594a,0x7de79e,0x1ef2b6,0x325d7b0,0x119afff}},{{0xd086a6,0x1d25fcf,0xe2f6c0,0x1c1eb7f,0x36cea89,0x75722b,0x13bee25,0xf2658f,0x1eff6a2,0xe520c2}}}};
static const struct Precomp precomp_b[9] = {{{{0x73383e,0x28b209,0x10a8976,0xe69cd2,0x22e4f64,0x458b51,0x1e17755,0x104ec90,0x648086,0x12f3a51}},{{0x388d0ad,0xaa04f6,0x1b83c7c,0x1eadd8a,0x1bd02c4,0x11e2bd2,0xaa12aa,0x12db8ce,0x2ec4643,0x10016de}},{{0x3ec791c,0x386096,0x2c4b990,0x857b6b,0x382d2a7,0x1bb2e98,0x29abe97,0x7b4c29,0x3663a64,0x71deed}}},{{{0x23e68e7,0xad566b,0x197a2da,0x19ac23d,0x1bf1589,0x290875,0x8faa4b,0x14cd731,0xf6ff38,0x10ea3f7}},{{0x17134b0,0x1b49d67,0x141bd3b,0x9aa3d8,0x39ef2d6,0x7344fb,0x232f801,0x14ebd7,0xf89bc8,0x1993cd6}},{{0x315ebb4,0x10e5919,0x7e27ba,0x189df25,0x45364b,0x1d4c159,0x1c5b3ab,0x190bc28,0x1c7cef6,0x146d5f2}}},{{{0x44781,0x10f816b,0xca5322,0x1363394,0x15603f6,0x15bcd2,0x2426c86,0xcae7de,0x1e48ce2,0x767670}},{{0x20dd5c9,0xc6d956,0x17a63e6,0x10e4c31,0x2d517d,0x1737833,0x3c4d98a,0x8b8732,0x107743d,0x4d41ce}},{{0x1ad1eab,0x218bfd,0x22f427c,0x1cc838e,0x3fbe98e,0x1828ceb,0x3b349f9,0xab5b06,0x314a5d0,0x295b9e}}},{{{0x15f8c9c,0x1f39a89,0x11dd5b9,0xe4a24,0x22f61dd,0x445bfd,0x14a6a02,0x914127,0x33fce91,0x1ec9447}},{{0x3235b3e,0x91bdef,0x3b96248,0xa0f6c3,0x3a1f9b9,0x1385592,0x1761a60,0x1e26f0a,0x865425,0x1f0616a}},{{0x2d9afef,0x1e063a7,0x38332e9,0xb5833,0xccce4,0x165f0a5,0x24d6ed0,0xf6a88f,0x2014185,0x1659012}}},{{{0xbf0c8d,0x46c7f6,0x1d93ef1,0x5cf85d,0x2cd489e,0xcde233,0x30b9cd6,0x10b8104,0x14f2d9c,0x1b9a21d}},{{0x944a2d,0xe3e461,0x200904c,0x16cbc11,0x18552ba,0x1c0acee,0x1a4ef97,0x1380f14,0x2447e05,0x46ab76}},{{0x254cfb9,0xccf67c,0x7b546c,0xa06f7e,0x2fbe0f1,0x16fcaa2,0x37c61fa,0x1b771d2,0x234b77a,0x10b32c8}}},{{{0x3fdd933,0xbf5a1d,0x3c8599a,0x1f21bac,0x209ddbb,0x97c374,0x27a4ff2,0x1835bd8,0x1748248,0x17911a5}},{{0x39a71ab,0x20310b,0xc74c7f,0x1848810,0x1142e46,0x291bd1,0xbe416a,0x16dc8dd,0x33f8a8f,0x10f4bfa}},{{0x3091ffe,0x1459d25,0xe10517,0x84ea5d,0x1c0a657,0x100ed94,0x3e98d2f,0x579f66,0x2f9f141,0x553bef}}},{{{0x16053a2,0xcbb205,0x22520af,0x13797ec,0x36b2d0,0x110ddd5,0x2c6905e,0x65dc61,0x1d079bb,0x9ede5a}},{{0x31a119d,0x19d2c09,0x3e8410f,0x1385870,0x19f0380,0x12b648f,0x241ce86,0x1517ddb,0x16fb9c8,0x1ab9a82}},{{0x8d8281,0x10f96a4,0x19a34e4,0xd47a8c,0x1cb8633,0x18ddcac,0x1f41d8f,0x1679e5c,0x3abd8f7,0x1c344f6}}},{{{0x3fbb842,0x1bad9d1,0x351626f,0x1ab0408,0x1e77d71,0x1f8c89a,0x1d3b7b8,0x1f84b45,0x163bc8f,0x2654a9}},{{0x7ef83c,0x32d2f7,0x44d455,0x1d2fc9e,0x25ad71b,0x64e3a5,0x1f58d83,0x1e5fa9d,0x1ce5c6c,0x1026d2b}},{{0x34350c4,0x14f6e60,0xb6889a,0x2d2fa8,0x224a64c,0x149ff2f,0x17d512c,0x1ac9f64,0x2704657,0x1a6e5a2}}},{{{0x18c3b85,0x124f1bd,0x1c325f7,0x37dc60,0x33e4cb7,0x3d42c2,0x1a44c32,0x14ca4e1,0x3a33d4b,0x1f3e74}},{{0x340913e,0xe4175,0x3d673a2,0x2e8a05,0x3f4e67c,0x8f8a09,0xc21a34,0x4cf4b8,0x1298f81,0x113f4be}},{{0x37aaa68,0x448161,0x93d579,0x11e6556,0x9b67a0,0x143598c,0x1bee5ee,0xb50b43,0x289f0c6,0x1bc45ed}}}};

static void mul(union Fe* out, const union Fe* f, const union Fe* g) {
    uint32_t f0 = f->v[0];
    uint32_t f1 = f->v[1];
    uint32_t f2 = f->v[2];
    uint32_t f3 = f->v[3];
    uint32_t f4 = f->v[4];
    uint32_t f5 = f->v[5];
    uint32_t f6 = f->v[6];
    uint32_t f7 = f->v[7];
    uint32_t f8 = f->v[8];
    uint32_t f9 = f->v[9];
    uint32_t g0 = g->v[0];
    uint32_t g1 = g->v[1];
    uint32_t g2 = g->v[2];
    uint32_t g3 = g->v[3];
    uint32_t g4 = g->v[4];
    uint32_t g5 = g->v[5];
    uint32_t g6 = g->v[6];
    uint32_t g7 = g->v[7];
    uint32_t g8 = g->v[8];
    uint32_t g9 = g->v[9];


    uint64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;

    h9 = (uint64_t)f1 * g8;
    h8 = (uint64_t)f1 * g7;
    h7 = (uint64_t)f1 * g6;
    h6 = (uint64_t)f1 * g5;
    h9 += (uint64_t)f3 * g6;
    h8 += (uint64_t)f3 * g5;
    h7 += (uint64_t)f3 * g4;
    h6 += (uint64_t)f3 * g3;
    h9 += (uint64_t)f5 * g4;
    h8 += (uint64_t)f5 * g3;
    h7 += (uint64_t)f5 * g2;
    h6 += (uint64_t)f5 * g1;
    h9 += (uint64_t)f7 * g2;
    h8 += (uint64_t)f7 * g1;
    h7 += (uint64_t)f7 * g0;

    f7 *= 19;
    uint32_t f9_19 = f9 * 19;
    uint32_t f8_19 = f8 * 19;
    uint32_t f6_19 = f6 * 19;

    h6 += (uint64_t)f7 * g9;
    h9 += (uint64_t)f9 * g0;
    h8 += (uint64_t)f9_19 * g9;
    h7 += (uint64_t)f9_19 * g8;
    h6 += (uint64_t)f9_19 * g7;

    h8 += h8;
    h9 += (uint64_t)f0 * g9;
    h6 += h6;
    h8 += (uint64_t)f0 * g8;
    h7 += (uint64_t)f0 * g7;
    h6 += (uint64_t)f0 * g6;

    h9 += (uint64_t)f2 * g7;
    h8 += (uint64_t)f2 * g6;
    h7 += (uint64_t)f2 * g5;
    h6 += (uint64_t)f2 * g4;

    h9 += (uint64_t)f4 * g5;
    h8 += (uint64_t)f4 * g4;
    h7 += (uint64_t)f4 * g3;
    h6 += (uint64_t)f4 * g2;

    h9 += (uint64_t)f6 * g3;
    h8 += (uint64_t)f6 * g2;
    h7 += (uint64_t)f6 * g1;
    h6 += (uint64_t)f6 * g0;

    h9 += (uint64_t)f8 * g1;
    h8 += (uint64_t)f8 * g0;
    h7 += (uint64_t)f8_19 * g9;
    h6 += (uint64_t)f8_19 * g8;

    h5 = (uint64_t)f9_19 * g6;
    h4 = (uint64_t)f9_19 * g5;
    h3 = (uint64_t)f9_19 * g4;

    h5 += (uint64_t)f5 * g0;
    f5 *= 19;
    h4 += (uint64_t)f7 * g7;
    h3 += (uint64_t)f7 * g6;

    h5 += (uint64_t)f7 * g8;
    h4 += (uint64_t)f5 * g9;
    h3 += (uint64_t)f5 * g8;

    h5 += (uint64_t)f3 * g2;
    h4 += (uint64_t)f3 * g1;
    h3 += (uint64_t)f3 * g0;

    h5 += (uint64_t)f1 * g4;
    h4 += (uint64_t)f1 * g3;
    h3 += (uint64_t)f1 * g2;

    uint32_t f4_19 = f4 * 19;
    h4 += h4;
    h5 += (uint64_t)f8_19 * g7;
    h4 += (uint64_t)f8_19 * g6;
    h3 += (uint64_t)f8_19 * g5;

    h5 += (uint64_t)f6_19 * g9;
    h4 += (uint64_t)f6_19 * g8;
    h3 += (uint64_t)f6_19 * g7;

    h5 += (uint64_t)f4 * g1;
    h4 += (uint64_t)f4 * g0;
    h3 += (uint64_t)f4_19 * g9;

    h5 += (uint64_t)f2 * g3;
    h4 += (uint64_t)f2 * g2;
    h3 += (uint64_t)f2 * g1;

    h5 += (uint64_t)f0 * g5;
    h4 += (uint64_t)f0 * g4;
    h3 += (uint64_t)f0 * g3;

    uint32_t f3_19 = f3 * 19;
    h5 += h4 >> 26;
    h4 &= 0x3ffffff;
    h6 += h5 >> 25;
    h5 &= 0x1ffffff;
    h7 += h6 >> 26;
    h6 &= 0x3ffffff;
    h8 += h7 >> 25;
    h7 &= 0x1ffffff;
    h9 += h8 >> 26;
    h8 &= 0x3ffffff;

    uint64_t o1 = h9 & ~0x3ffffff;
    h0 = o1 >> 26;
    h9 &= 0x3ffffff;
    h0 += o1 >> 25;
    h2 = (uint64_t)f9_19 * g3;
    h0 += o1 >> 22;
    h1 = (uint64_t)f9_19 * g2;
    h0 += (uint64_t)f9_19 * g1;

    h2 += (uint64_t)f7 * g5;
    h1 += (uint64_t)f7 * g4;
    h0 += (uint64_t)f7 * g3;

    uint32_t f1_19 = f1 * 19;
    h1 += (uint64_t)f5 * g6;
    h0 += (uint64_t)f5 * g5;
    h2 += (uint64_t)f5 * g7;

    h1 += (uint64_t)f3_19 * g8;
    h0 += (uint64_t)f3_19 * g7;
    h2 += (uint64_t)f3_19 * g9;

    h1 += (uint64_t)f1 * g0;
    h0 += (uint64_t)f1_19 * g9;
    h2 += (uint64_t)f1 * g1;

    uint32_t f2_19 = f2 * 19;
    h0 += h0;
    h2 += h2;

    h0 += (uint64_t)f8_19 * g2;
    h1 += (uint64_t)f8_19 * g3;
    h2 += (uint64_t)f8_19 * g4;

    h0 += (uint64_t)f6_19 * g4;
    h1 += (uint64_t)f6_19 * g5;
    h2 += (uint64_t)f6_19 * g6;

    h0 += (uint64_t)f4_19 * g6;
    h1 += (uint64_t)f4_19 * g7;
    h2 += (uint64_t)f4_19 * g8;

    h0 += (uint64_t)f2_19 * g8;
    h1 += (uint64_t)f2_19 * g9;
    h2 += (uint64_t)f2 * g0;

    h0 += (uint64_t)f0 * g0;
    h1 += (uint64_t)f0 * g1;
    h2 += (uint64_t)f0 * g2;

    h1 += h0 >> 26;
    h0 &= 0x3ffffff;
    h2 += h1 >> 25;
    h1 &= 0x1ffffff;
    h3 += h2 >> 26;
    h2 &= 0x3ffffff;
    h4 += h3 >> 25;
    h3 &= 0x1ffffff;
    h5 += h4 >> 26;
    h4 &= 0x3ffffff;
    h5 &= 0x3ffffff;

    out->v[0] = (uint32_t)h0;
    out->v[1] = (uint32_t)h1;
    out->v[2] = (uint32_t)h2;
    out->v[3] = (uint32_t)h3;
    out->v[4] = (uint32_t)h4;
    out->v[5] = (uint32_t)h5;
    out->v[6] = (uint32_t)h6;
    out->v[7] = (uint32_t)h7;
    out->v[8] = (uint32_t)h8;
    out->v[9] = (uint32_t)h9;
}

static void sqr(union Fe* out, const union Fe* f) {
    uint32_t f0 = f->v[0];
    uint32_t f1 = f->v[1];
    uint32_t f2 = f->v[2];
    uint32_t f3 = f->v[3];
    uint32_t f4 = f->v[4];
    uint32_t f5 = f->v[5];
    uint32_t f6 = f->v[6];
    uint32_t f7 = f->v[7];
    uint32_t f8 = f->v[8];
    uint32_t f9 = f->v[9];

    uint32_t f9_2 = (f9 + f9);
    uint32_t f8_2 = (f8 + f8);
    uint32_t f7_2 = (f7 + f7);
    uint32_t f6_2 = (f6 + f6);
    uint32_t f5_2 = (f5 + f5);
    uint32_t f4_2 = (f4 + f4);
    uint32_t f3_2 = (f3 + f3);
    uint32_t f2_2 = (f2 + f2);
    uint32_t f1_2 = (f1 + f1);

    uint64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;

    h8 = (uint64_t)f4 * f4;
    h9 = (uint64_t)f4 * f5_2;

    f9 = f9 * 19;
    f7 = f7 * 19;
    f5 = f5 * 19;

    h8 += (uint64_t)f9 * f9_2;
    h9 += (uint64_t)f0 * f9_2;

    h0 = (uint64_t)f0 * f0;
    h1 = (uint64_t)f0 * f1_2;
    h2 = (uint64_t)f0 * f2_2;
    h3 = (uint64_t)f0 * f3_2;
    h4 = (uint64_t)f0 * f4_2;
    h5 = (uint64_t)f0 * f5_2;
    h6 = (uint64_t)f0 * f6_2;
    h7 = (uint64_t)f0 * f7_2;
    h8 += (uint64_t)f0 * f8_2;
    uint32_t f6_19 = f6 * 19;

    h2 += (uint64_t)f1 * f1_2;
    h3 += (uint64_t)f1 * f2_2;
    h4 += (uint64_t)f1_2 * f3_2;
    h5 += (uint64_t)f1 * f4_2;
    h6 += (uint64_t)f1_2 * f5_2;
    h7 += (uint64_t)f1 * f6_2;
    h8 += (uint64_t)f1_2 * f7_2;
    h9 += (uint64_t)f1 * f8_2;
    uint32_t f8_19 = f8 * 19;

    h4 += (uint64_t)f2 * f2;
    h5 += (uint64_t)f2 * f3_2;
    h6 += (uint64_t)f2 * f4_2;
    h7 += (uint64_t)f2 * f5_2;
    h8 += (uint64_t)f2 * f6_2;
    h9 += (uint64_t)f2 * f7_2;

    h6 += (uint64_t)f3 * f3_2;
    h7 += (uint64_t)f3 * f4_2;
    h8 += (uint64_t)f3_2 * f5_2;
    h9 += (uint64_t)f3 * f6_2;

    h6 += (uint64_t)f8_19 * f8;
    h2 += (uint64_t)f6_19 * f6;

    h9 += h8 >> 26;
    h0 += (uint64_t)f5 * f5_2;
    h0 += h9 >> 25;
    uint64_t o = h9 & ~0x1ffffffULL;
    h0 += o >> 24;
    h9 &= 0x1ffffff;
    h0 += o >> 21;

    h4 += (uint64_t)f7 * f7_2;

    uint32_t f1_4 = (f1_2 + f1_2);
    uint32_t f3_4 = (f3_2 + f3_2);
    uint32_t f5_4 = (f5_2 + f5_2);
    uint32_t f7_4 = (f7_2 + f7_2);

    h0 += (uint64_t)f6_19 * f4_2;
    h1 += (uint64_t)f6_19 * f5_2;

    h8 &= 0x3ffffff;

    h0 += (uint64_t)f7 * f3_4;
    h1 += (uint64_t)f7 * f4_2;
    h2 += (uint64_t)f7 * f5_4;
    h3 += (uint64_t)f7 * f6_2;

    h0 += (uint64_t)f8_19 * f2_2;
    h1 += (uint64_t)f8_19 * f3_2;
    h2 += (uint64_t)f8_19 * f4_2;
    h3 += (uint64_t)f8_19 * f5_2;
    h4 += (uint64_t)f8_19 * f6_2;
    h5 += (uint64_t)f8_19 * f7_2;

    h0 += (uint64_t)f9 * f1_4;
    h1 += (uint64_t)f9 * f2_2;
    h2 += (uint64_t)f9 * f3_4;
    h3 += (uint64_t)f9 * f4_2;
    h4 += (uint64_t)f9 * f5_4;
    h5 += (uint64_t)f9 * f6_2;
    h6 += (uint64_t)f9 * f7_4;
    h7 += (uint64_t)f9 * f8_2;

    h1 += h0 >> 26;
    h0 &= 0x3ffffff;
    h2 += h1 >> 25;
    h1 &= 0x1ffffff;
    h3 += h2 >> 26;
    h2 &= 0x3ffffff;
    h4 += h3 >> 25;
    h3 &= 0x1ffffff;
    h5 += h4 >> 26;
    h4 &= 0x3ffffff;
    h6 += h5 >> 25;
    h5 &= 0x1ffffff;
    h7 += h6 >> 26;
    h6 &= 0x3ffffff;
    h8 += h7 >> 25;
    h7 &= 0x1ffffff;
    h9 += h8 >> 26;
    h8 &= 0x3ffffff;
    //h9 &= 0x3ffffff;

    out->v[0] = (uint32_t)h0;
    out->v[1] = (uint32_t)h1;
    out->v[2] = (uint32_t)h2;
    out->v[3] = (uint32_t)h3;
    out->v[4] = (uint32_t)h4;
    out->v[5] = (uint32_t)h5;
    out->v[6] = (uint32_t)h6;
    out->v[7] = (uint32_t)h7;
    out->v[8] = (uint32_t)h8;
    out->v[9] = (uint32_t)h9;
}

static void mul121666(union Fe* out, const union Fe* f) {
    uint64_t h0 = (uint64_t)f->v[0] * 121666, h1 = (uint64_t)f->v[1] * 121666, h2 = (uint64_t)f->v[2] * 121666, h3 = (uint64_t)f->v[3] * 121666, h4 = (uint64_t)f->v[4] * 121666;
    uint64_t h5 = (uint64_t)f->v[5] * 121666, h6 = (uint64_t)f->v[6] * 121666, h7 = (uint64_t)f->v[7] * 121666, h8 = (uint64_t)f->v[8] * 121666, h9 = (uint64_t)f->v[9] * 121666;

    h0 += (h9 >> 25) * 19;
    h9 &= 0x1ffffff;

    h1 += h0 >> 26;
    out->v[0] = (uint32_t)h0 & 0x3ffffff;
    h2 += h1 >> 25;
    out->v[1] = (uint32_t)h1 & 0x1ffffff;
    h3 += h2 >> 26;
    out->v[2] = (uint32_t)h2 & 0x3ffffff;
    h4 += h3 >> 25;
    out->v[3] = (uint32_t)h3 & 0x1ffffff;
    h5 += h4 >> 26;
    out->v[4] = (uint32_t)h4 & 0x3ffffff;
    h6 += h5 >> 25;
    out->v[5] = (uint32_t)h5 & 0x1ffffff;
    h7 += h6 >> 26;
    out->v[6] = (uint32_t)h6 & 0x3ffffff;
    h8 += h7 >> 25;
    out->v[7] = (uint32_t)h7 & 0x1ffffff;
    h9 += h8 >> 26;
    out->v[8] = (uint32_t)h8 & 0x3ffffff;
    out->v[9] = (uint32_t)h9;
}

static void add(union Fe* out, const union Fe* f, const union Fe* g) {
    out->v[0] = f->v[0] + g->v[0];
    out->v[1] = f->v[1] + g->v[1];
    out->v[2] = f->v[2] + g->v[2];
    out->v[3] = f->v[3] + g->v[3];
    out->v[4] = f->v[4] + g->v[4];
    out->v[5] = f->v[5] + g->v[5];
    out->v[6] = f->v[6] + g->v[6];
    out->v[7] = f->v[7] + g->v[7];
    out->v[8] = f->v[8] + g->v[8];
    out->v[9] = f->v[9] + g->v[9];
}

static void sub(union Fe* out, const union Fe* f, const union Fe* g) {
    out->v[0] = f->v[0] - g->v[0] + 0x7ffffb4;
    out->v[1] = f->v[1] - g->v[1] + 0x7fffffe;
    out->v[2] = f->v[2] - g->v[2] + 0x7fffffc;
    out->v[3] = f->v[3] - g->v[3] + 0x7fffffe;
    out->v[4] = f->v[4] - g->v[4] + 0x7fffffc;
    out->v[5] = f->v[5] - g->v[5] + 0x7fffffe;
    out->v[6] = f->v[6] - g->v[6] + 0x7fffffc;
    out->v[7] = f->v[7] - g->v[7] + 0x7fffffe;
    out->v[8] = f->v[8] - g->v[8] + 0x7fffffc;
    out->v[9] = f->v[9] - g->v[9] + 0x7fffffe;
}

static void reduce_once(union Fe* f) {
    uint32_t f0 = f->v[0];
    uint32_t f1 = f->v[1];
    uint32_t f2 = f->v[2];
    uint32_t f3 = f->v[3];
    uint32_t f4 = f->v[4];
    uint32_t f5 = f->v[5];
    uint32_t f6 = f->v[6];
    uint32_t f7 = f->v[7];
    uint32_t f8 = f->v[8];
    uint32_t f9 = f->v[9];

    f0 += (f9 >> 25) * 19;
    f9 &= 0x1ffffff;

    f1 += f0 >> 26;
    f0 &= 0x3ffffff;
    f2 += f1 >> 25;
    f1 &= 0x1ffffff;
    f3 += f2 >> 26;
    f2 &= 0x3ffffff;
    f4 += f3 >> 25;
    f3 &= 0x1ffffff;
    f5 += f4 >> 26;
    f4 &= 0x3ffffff;
    f6 += f5 >> 25;
    f5 &= 0x1ffffff;
    f7 += f6 >> 26;
    f6 &= 0x3ffffff;
    f8 += f7 >> 25;
    f7 &= 0x1ffffff;
    f9 += f8 >> 26;
    f8 &= 0x3ffffff;

    f->v[0] = f0;
    f->v[1] = f1;
    f->v[2] = f2;
    f->v[3] = f3;
    f->v[4] = f4;
    f->v[5] = f5;
    f->v[6] = f6;
    f->v[7] = f7;
    f->v[8] = f8;
    f->v[9] = f9;
}

static void sqr_many(union Fe* out, const union Fe* in, int times) {
    sqr(out, in);
    for (int i = 1; i < times; i++) {
        sqr(out, out);
    }
}

static void inv(union Fe* out, const union Fe* in) {
    union Fe t0, t1, t2, t3;

    sqr(&t0, in);               // 2^1
    sqr(&t1, &t0);            // 2^2
    sqr(&t1, &t1);            // 2^3
    mul(&t1, &t1, in);      // 2^3 + 2^0 = 9
    mul(&t0, &t1, &t0);   // 9 + 2^1 = 11
    sqr(&t2, &t0);            // 11*2 = 22
    mul(&t1, &t2, &t1);   // 22 + 9 = 2^5 - 2^0
    sqr_many(&t2, &t1, 5);      // 2^10 - 2^5
    mul(&t1, &t2, &t1);   // 2^10 - 2^0
    sqr_many(&t2, &t1, 10);     // 2^20 - 2^10
    mul(&t2, &t2, &t1);   // 2^20 - 2^0
    sqr_many(&t3, &t2, 20);     // 2^40 - 2^20
    mul(&t2, &t3, &t2);   // 2^40 - 2^0
    sqr_many(&t2, &t2, 10);     // 2^50 - 2^10
    mul(&t1, &t2, &t1);   // 2^50 - 2^0
    sqr_many(&t2, &t1, 50);     // 2^100 - 2^50
    mul(&t2, &t2, &t1);   // 2^100 - 2^0
    sqr_many(&t3, &t2, 100);    // 2^200 - 2^100
    mul(&t2, &t3, &t2);   // 2^200 - 2^0
    sqr_many(&t2, &t2, 50);     // 2^250 - 2^50
    mul(&t2, &t2, &t1);   // 2^250 - 2^0
    sqr_many(&t2, &t2, 5);  // 2^255 - 2^5
    mul(out, &t2, &t0);  // 2^255 - 21
}

static void csel(union Fe* out, const union Fe* in1, const union Fe* in2, int sel) {
    int sel0 = sel - 1;
    int sel1 = -sel;
    out->l[0] = (in1->l[0] & sel0) | (in2->l[0] & sel1);
    out->l[1] = (in1->l[1] & sel0) | (in2->l[1] & sel1);
    out->l[2] = (in1->l[2] & sel0) | (in2->l[2] & sel1);
    out->l[3] = (in1->l[3] & sel0) | (in2->l[3] & sel1);
    out->l[4] = (in1->l[4] & sel0) | (in2->l[4] & sel1);
}

static uint64_t load_long(const uint8_t* in) {
    return (uint32_t)((in[0]) | ((in[1]) << 8) | ((in[2]) << 16) | ((in[3]) << 24)) |
            ((uint64_t)(in[4]) << 32) | ((uint64_t)(in[5]) << 40) | ((uint64_t)(in[6]) << 48) | ((uint64_t)(in[7]) << 56);
}

static void from_bytes(union Fe* out, const uint8_t in[32]) {
    uint64_t v0 = load_long(in);
    uint64_t v1 = load_long(in + 8);
    uint64_t v2 = load_long(in + 16);
    uint64_t v3 = load_long(in + 24);
    out->v[0] = (v0 & 0x3ffffff);
    out->v[1] = ((v0 >> 26) & 0x1ffffff);
    out->v[2] = (uint32_t)((v0 >> 51) | ((v1 & 0x1fff) << 13));
    out->v[3] = ((v1 >> 13) & 0x1ffffff);
    out->v[4] = (v1 >> 38);
    out->v[5] = (v2 & 0x1ffffff);
    out->v[6] = ((v2 >> 25) & 0x3ffffff);
    out->v[7] = (uint32_t)((v2 >> 51) | (v3 & 0xfff) << 13);
    out->v[8] = ((v3 >> 12) & 0x3ffffff);
    out->v[9] = ((v3 >> 38) & 0x1ffffff);
}

static void store_long(uint8_t* out, uint64_t v) {
    out[0] = v;
    out[1] = (v >> 8);
    out[2] = (v >> 16);
    out[3] = (v >> 24);
    out[4] = (v >> 32);
    out[5] = (v >> 40);
    out[6] = (v >> 48);
    out[7] = (v >> 56);
}

static uint32_t add_overflows(uint64_t a, uint64_t b) {
    return (uint32_t)((((a & 0x7fffffffffffffffULL) + (b & 0x7fffffffffffffffULL)) >> 63) + (a >> 63) + (b >> 63)) >> 1;
}

static void to_bytes(uint8_t out[32], const union Fe* in) {
    // We take care of when in.g and in.j have 26 bits

    uint64_t v0 = in->v[0] | ((uint64_t)in->v[1] << 26) | ((uint64_t)in->v[2] << 51);
    uint64_t v1 = (in->v[2] >> 13) | ((uint64_t)in->v[3] << 13) | ((uint64_t)in->v[4] << 38);
    uint64_t v2 = in->v[5] + ((uint64_t)in->v[6] << 25);
    uint64_t v2_2 = ((uint64_t)in->v[7] << 51);
    uint64_t v3 = (in->v[7] >> 13) | ((uint64_t)in->v[8] << 12) | ((uint64_t)in->v[9] << 38);

    uint32_t v3_extra = add_overflows(v2, v2_2);
    v2 += v2_2;
    uint32_t v4 = add_overflows(v3, v3_extra);
    v3 += v3_extra;

    uint32_t tst = ((uint32_t)(v3 >> 63) | (v4 << 1)) * 19 + 19;

    tst = add_overflows(v0, tst);
    tst = add_overflows(v1, tst);
    tst = add_overflows(v2, tst);
    uint32_t carry = add_overflows(v3, tst);
    carry = (uint32_t)(((v4 + carry) << 1) | ((v3 + tst) >> 63) * 19);

    uint32_t carry2 = add_overflows(v0, carry);
    v0 += carry;
    carry = add_overflows(v1, carry2);
    v1 += carry2;
    carry2 = add_overflows(v2, carry);
    v2 += carry;
    v3 = (v3 + carry2) & 0x7fffffffffffffffULL;

    store_long(out, v0);
    store_long(out + 8, v1);
    store_long(out + 16, v2);
    store_long(out + 24, v3);
}

void curve25519(uint8_t out[32], const uint8_t point[32], const uint8_t scalar[32]) {
    union Fe x;
    from_bytes(&x, point);
    union Fe x2, z2, x3 = x, z3;
    union Fe b, d, a, c, aa, bb, e;
    union Fe f, g, da, cb, t1, t2;

    x2.v[0] = 1;
    z3.v[0] = 1;
    memset(&x2.v[1], 0, 36);
    memset(&z3.v[1], 0, 36);
    memset(&z2, 0, 40);

    uint8_t sc[32];
    memcpy(sc, scalar, 32);
    sc[31] = ((sc[31] & 0x7f) | 0x40);
    sc[0] &= 0xf8;

    int last = 0;
    for (int i = 255; i >= 0; i--) {
        int bit = (sc[i >> 3] >> (i & 7)) & 1;
        int val = bit ^ last;
        last = bit;
        sub(&b, &x2, &z2);
        sub(&d, &x3, &z3);
        add(&a, &x2, &z2);
        add(&c, &x3, &z3);
        csel(&f, &a, &c, val);
        csel(&g, &b, &d, val);
        sqr(&aa, &f);
        sqr(&bb, &g);
        sub(&e, &aa, &bb);
        mul121666(&z2, &e);
        add(&z2, &bb, &z2);
        mul(&z2, &z2, &e);
        mul(&da, &d, &a);
        mul(&cb, &c, &b);
        add(&t1, &da, &cb);
        sub(&t2, &da, &cb);
        sqr(&x3, &t1);
        sqr(&t2, &t2);
        mul(&x2, &aa, &bb);
        mul(&z3, &x, &t2);
    }
    inv(&z2, &z2);
    mul(&x2, &x2, &z2);
    to_bytes(out, &x2);
}

static void edwards_dbl(union Fe* outT, union Fe* outX, union Fe* outY, union Fe* outZ, union Fe* inX, union Fe* inY, union Fe* inZ, union Fe* tmp) {
    add(tmp, inX, inY);
    sqr(tmp, tmp);
    sqr(outX, inX);
    sqr(outT, inZ);
    add(outT, outT, outT);
    sqr(outZ, inY);
    add(outT, outT, outX);
    sub(outT, outT, outZ);
    add(outY, outX, outZ);
    reduce_once(outY);
    sub(outZ, outZ, outX);
    sub(outX, tmp, outY);
}

// overwrites inT
static void edwards_add_sub(union Fe* outT, union Fe* outX, union Fe* outY, union Fe* outZ, union Fe* inX, union Fe* inY, union Fe* inZ, union Fe* inT, bool do_sub, const union Fe* qYpX, const union Fe* qYmX, const union Fe* qT2d) {
    add(outT, inY, inX);
    sub(outY, inY, inX);
    mul(outT, outT, do_sub ? qYmX : qYpX);
    mul(outY, outY, do_sub ? qYpX : qYmX);
    sub(outX, outT, outY);
    add(outY, outT, outY);
    mul(inT, qT2d, inT);
    add(outZ, inZ, inZ);
    if (do_sub) {
        add(outT, outZ, inT);
        sub(outZ, outZ, inT);
        reduce_once(outZ);
    } else {
        sub(outT, outZ, inT);
        add(outZ, outZ, inT);
    }
}

static void edwards_p1p1_to_p3(union Fe* outX, union Fe* outY, union Fe* outZ, union Fe* outT, union Fe* inT, union Fe* inX, union Fe* inY, union Fe* inZ) {
    mul(outT, inY, inX);
    mul(outX, inX, inT);
    mul(outY, inY, inZ);
    mul(outZ, inZ, inT);
}

static void edwards_p1p1_to_p2(union Fe* outX, union Fe* outY, union Fe* outZ, union Fe* inT, union Fe* inX, union Fe* inY, union Fe* inZ) {
    mul(outX, inX, inT);
    mul(outY, inY, inZ);
    mul(outZ, inZ, inT);
}

static void mul288x288(uint32_t out[18], const uint32_t in1[9], const uint32_t in2[9]) {
    const uint16_t* a = (const uint16_t*)in1;
    const uint16_t* b = (const uint16_t*)in2;
    uint16_t* o = (uint16_t*)out;
    
    memset(out, 0, 9 * sizeof(uint32_t));
    
    for (int i = 0; i < 18; i++) {
        uint32_t carry = 0;
        uint16_t a_val = a[i];
        for (int j = 0; j < 18; j++) {
            uint32_t m = (uint32_t)a_val * b[j] + carry + o[i + j];
            o[i + j] = m;
            carry = m >> 16;
        }
        o[i + 18] = carry;
    }
}

static void reduce_scalar_32bytes(uint32_t val[8]) {
    uint32_t borrow = 0;
    do {
        for (int i = 0; i < 8; i++) {
            uint64_t v = (uint64_t)val[i] - basepoint_order[i] - borrow;
            val[i] = (uint32_t)v;
            borrow = v >> 63;
        }
    } while (!borrow);
    uint32_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t v = (uint64_t)val[i] + basepoint_order[i] + carry;
        val[i] = (uint32_t)v;
        carry = v >> 32;
    }
}

static void reduce_scalar_64bytes(uint32_t val[16]) {
    // Barrett Reduction
    uint32_t buf[27];
    mul288x288(buf + 9, val + 7, basepoint_mu);
    mul288x288(buf, buf + 18, basepoint_order);
    
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t v = (uint64_t)val[i] - buf[i] - borrow;
        val[i] = (uint32_t)v;
        borrow = v >> 63;
    }
    // Now out < 3 * basepoint_order, so reduce at most two times
    reduce_scalar_32bytes(val);
}

static uint32_t load_int(const uint8_t* in) {
    return (in[0]) | (in[1] << 8) | (in[2] << 16) | (in[3] << 24);
}

static void inv4(union Fe* a, union Fe* b, union Fe* c, union Fe* d) {
    union Fe ab, cd, z;
    mul(&ab, a, b);
    mul(&cd, c, d);
    mul(&z, &ab, &cd);
    inv(&z, &z);
    mul(&ab, &ab, &z);
    mul(&cd, &cd, &z);
    z = *a;
    mul(a, &cd, b);
    mul(b, &cd, &z);
    z = *c;
    mul(c, &ab, d);
    mul(d, &ab, &z);
}

static bool ed25519_verify_hram(const uint8_t signature[64], const uint8_t hram[64], uint8_t* correct_bits) {
    if ((signature[63] & 0xe0) != 0) {
        return false;
    }
    uint32_t a_scalar[16];
    for (int i = 0; i < 16; i++) {
        a_scalar[i] = load_int(hram + i * 4);
    }
    reduce_scalar_64bytes(a_scalar);

    uint8_t b_scalar[33];
    for (int i = 0; i < 32; i++) {
        b_scalar[i] = signature[32 + i];
    }

    union Fe tX, tY, tZ, tT1, tT2;
    tY.v[0] = 1;
    tZ.v[0] = 1;
    memset(&tY.v[1], 0, 36);
    memset(&tZ.v[1], 0, 36);
    memset(&tX, 0, 40);

    a_scalar[8] = 1;
    b_scalar[32] = 1;
    b_scalar[0] |= 3;

    for (int i = 64; i > 0; i--) {
        edwards_dbl(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2);

        int i_mod_32 = i & 31;
        int a = ((a_scalar[i >> 5] >> i_mod_32) & 1) |
                (((a_scalar[(i + 64) >> 5] >> i_mod_32) & 1) << 1) |
                (((a_scalar[(i + 128) >> 5] >> i_mod_32) & 1) << 2);
        int negate_a = 1 - ((a_scalar[(i + 192) >> 5] >> i_mod_32) & 1);
        if (negate_a != 0) {
            a = ~a & 7;
        }
        const struct Precomp* qA = &precomp_a[a];

        edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
        edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, negate_a == 0, &qA->y_p_x, &qA->y_m_x, &qA->t_2d);

        int i_mod_8 = i & 7;
        int b = ((b_scalar[i >> 3] >> i_mod_8) & 1) |
                (((b_scalar[(i + 64) >> 3] >> i_mod_8) & 1) << 1) |
                (((b_scalar[(i + 128) >> 3] >> i_mod_8) & 1) << 2);
        int negate_b = 1 - ((b_scalar[(i + 192) >> 3] >> i_mod_8) & 1);
        if (negate_b != 0) {
            b = ~b & 7;
        }
        const struct Precomp* qB = &precomp_b[b];
        edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
        edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, negate_b != 0, &qB->y_p_x, &qB->y_m_x, &qB->t_2d);

        if (i > 1) {
            edwards_p1p1_to_p2(&tX, &tY, &tZ, &tT1, &tX, &tY, &tZ);
        }
    }

    if ((a_scalar[0] & 1) == 0) {
        const struct Precomp* qA = &precomp_a[8];
        edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
        edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, false, &qA->y_p_x, &qA->y_m_x, &qA->t_2d);
    }
    const struct Precomp* qB = &precomp_b[8];
    union Fe x1, y1, z1, x2, y2, z2, x3, y3, z3;
    edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
    x3 = tX, y3 = tY, z3 = tZ;
    edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, true, &qB->y_p_x, &qB->y_m_x, &qB->t_2d);
    edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
    x2 = tX, y2 = tY, z2 = tZ;
    edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, true, &qB->y_p_x, &qB->y_m_x, &qB->t_2d);
    edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
    x1 = tX, y1 = tY, z1 = tZ;
    edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, true, &qB->y_p_x, &qB->y_m_x, &qB->t_2d);
    edwards_p1p1_to_p2(&tX, &tY, &tZ, &tT1, &tX, &tY, &tZ);
    inv4(&tZ, &z1, &z2, &z3);
    struct {
        union Fe *x, *y, *z;
    } p[4] = {{&tX, &tY, &tZ}, {&x1, &y1, &z1}, {&x2, &y2, &z2}, {&x3, &y3, &z3}};
    for (int i = 0; i < 4; i++) {
        mul(p[i].x, p[i].x, p[i].z);
        mul(p[i].y, p[i].y, p[i].z);
        uint8_t y_bytes[32], x_bytes[32];
        to_bytes(y_bytes, p[i].y);
        to_bytes(x_bytes, p[i].x);
        y_bytes[31] |= x_bytes[0] << 7;
        if (memcmp(y_bytes, signature, 32) == 0) {
            *correct_bits = i;
            return true;
        }
    }
    *correct_bits = 4;
    return false;
    /*
    if ((b_scalar[0] & 1) == 0) {
        const struct Precomp* qB = &precomp_b[8];
        edwards_p1p1_to_p3(&tX, &tY, &tZ, &tT2, &tT1, &tX, &tY, &tZ);
        edwards_add_sub(&tT1, &tX, &tY, &tZ, &tX, &tY, &tZ, &tT2, true, &qB->y_p_x, &qB->y_m_x, &qB->t_2d);
    }
    edwards_p1p1_to_p2(&tX, &tY, &tZ, &tT1, &tX, &tY, &tZ);
    inv(&tZ, &tZ);
    mul(&tX, &tX, &tZ);
    mul(&tY, &tY, &tZ);
    uint8_t y_bytes[32], x_bytes[32];
    to_bytes(y_bytes, &tY);
    to_bytes(x_bytes, &tX);
    y_bytes[31] |= x_bytes[0] << 7;
    return memcmp(y_bytes, signature, 32) == 0;*/
}

typedef struct {
    uint64_t current_hash[8];
    union {
        uint64_t as_uint64[128 / 8];
        uint8_t as_bytes[128];
    } unprocessed;
    uint64_t num_bytes;
} SHA512_STATE;

#define IS_LITTLE_ENDIAN_CPU 1

static const uint64_t h_init[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint64_t k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define REV32(a) ( ((uint32_t)(a) << 24) | ((uint32_t)(a) >> 24) | (((uint32_t)(a) << 8) & 0xff0000) | (((uint32_t)(a) >> 8) & 0xff00) )
#define REV64(a) ( ((uint64_t)REV32(a) << 32) | REV32((a) >> 32) )

#define ROR64(a, cnt) ( ((a) >> (cnt)) | ((a) << (64 - (cnt))) )

static void sha512_internal(uint64_t current_hash[8], uint64_t value[16]) {
    uint64_t w[80];
    int i;
    
    for (i = 0; i < 16; i++) {
#if IS_LITTLE_ENDIAN_CPU
        w[i] = REV64(value[i]);
#else
        w[i] = value[i];
#endif
    }
    
    for (; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    
    uint64_t a, b, c, d, e, f, g, h;
    
    a = current_hash[0];
    b = current_hash[1];
    c = current_hash[2];
    d = current_hash[3];
    e = current_hash[4];
    f = current_hash[5];
    g = current_hash[6];
    h = current_hash[7];
    
    for (i = 0; i < 80; i++) {
        uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = h + S1 + ch + k[i] + w[i];
        uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
        uint64_t maj = (a & b) | (c & (a | b));
        uint64_t t2 = S0 + maj;
        
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    current_hash[0] += a;
    current_hash[1] += b;
    current_hash[2] += c;
    current_hash[3] += d;
    current_hash[4] += e;
    current_hash[5] += f;
    current_hash[6] += g;
    current_hash[7] += h;
}

static void sha512_init(SHA512_STATE* state) {
    int i;
    
    state->num_bytes = 0;
    for (i = 0; i < 8; i++) {
        state->current_hash[i] = h_init[i];
    }
}

static void sha512_update(SHA512_STATE* state, const uint8_t* value, uint64_t len) {
    uint64_t i;
    
    for (i = 0; i < len; i++) {
        state->unprocessed.as_bytes[(state->num_bytes++) % 128] = *value++;
        if ((state->num_bytes % 128) == 0) {
            sha512_internal(state->current_hash, state->unprocessed.as_uint64);
        }
    }
}

static void sha512_finish(SHA512_STATE* state, uint8_t hash[64]) {
    int i;
    uint64_t len = state->num_bytes * 8; // size in bits
    uint8_t one_bit_and_zeros = 0x80;
    sha512_update(state, &one_bit_and_zeros, 1);
    
    int32_t num_zeros_to_add = 112 - (state->num_bytes % 128);
    if (num_zeros_to_add < 0) {
        num_zeros_to_add += 128;
    }
    num_zeros_to_add += 8; // Upper 128 bits of length is always 0
    
    uint32_t zeros[] = {0, 0, 0, 0};
    while (num_zeros_to_add > 16) {
        sha512_update(state, (uint8_t*)zeros, 16);
        num_zeros_to_add -= 16;
    }
    sha512_update(state, (uint8_t*)zeros, num_zeros_to_add);
    
    
#if IS_LITTLE_ENDIAN_CPU
    len = REV64(len);
#endif
    sha512_update(state, (uint8_t*)&len, 8);
#if IS_LITTLE_ENDIAN_CPU
    for (i = 0; i < 8; i++) {
        state->current_hash[i] = REV64(state->current_hash[i]);
    }
#endif
    for (i = 0; i < 64; i++) {
        hash[i] = ((uint8_t*)state->current_hash)[i];
    }
}

static void ed25519_calc_hram(uint8_t hram[64], const uint8_t public_key[32], const uint8_t r[32], const uint8_t* message, uint32_t msg_len) {
    SHA512_STATE state;
    sha512_init(&state);
    sha512_update(&state, r, 32);
    sha512_update(&state, public_key, 32);
    sha512_update(&state, message, msg_len);
    sha512_finish(&state, hram);
}

bool ed25519_verify(const uint8_t signature[64], const uint8_t* message, uint32_t msg_len, uint8_t* correct_bits) {
    static const uint8_t pubkey_bytes[32] = {211, 63, 36, 64, 221, 84, 179, 27, 46, 29, 207, 64, 19, 46, 250, 65, 216, 248, 167, 71, 65, 104, 223, 64, 8, 245, 169, 95, 179, 176, 208, 34};

    uint8_t hram[64];
    ed25519_calc_hram(hram, pubkey_bytes, signature, message, msg_len);
    return ed25519_verify_hram(signature, hram, correct_bits);
}

static const uint32_t sha256_h_init[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define REV32(a) ( ((uint32_t)(a) << 24) | ((uint32_t)(a) >> 24) | (((uint32_t)(a) << 8) & 0xff0000) | (((uint32_t)(a) >> 8) & 0xff00) )
#define REV64(a) ( ((uint64_t)REV32(a) << 32) | REV32((a) >> 32) )

#define ROR32(a, cnt) ( ((a) >> (cnt)) | ((a) << (32 - (cnt))) )

static void sha256_internal(uint32_t current_hash[8], uint32_t value[16]) {
    uint32_t w[64];
    int i;
    
    for (i = 0; i < 16; i++) {
#if IS_LITTLE_ENDIAN_CPU
        w[i] = REV32(value[i]);
#else
        w[i] = value[i];
#endif
    }
    
    for (; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    
    uint32_t a, b, c, d, e, f, g, h;
    
    a = current_hash[0];
    b = current_hash[1];
    c = current_hash[2];
    d = current_hash[3];
    e = current_hash[4];
    f = current_hash[5];
    g = current_hash[6];
    h = current_hash[7];
    
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) | (c & (a | b));
        uint32_t t2 = S0 + maj;
        
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    current_hash[0] += a;
    current_hash[1] += b;
    current_hash[2] += c;
    current_hash[3] += d;
    current_hash[4] += e;
    current_hash[5] += f;
    current_hash[6] += g;
    current_hash[7] += h;
}

void sha256_init(SHA256_STATE* state) {
    int i;
    
    state->num_bytes = 0;
    for (i = 0; i < 8; i++) {
        state->current_hash[i] = sha256_h_init[i];
    }
}

void sha256_update(SHA256_STATE* state, const uint8_t* value, size_t len) {
    size_t i = 0;
    
    while (i < len) {
        size_t left_to_copy = len - i;
        size_t left_in_buffer = 64 - (state->num_bytes % 64);
        size_t chunk_size = left_to_copy < left_in_buffer ? left_to_copy : left_in_buffer;
        memcpy(state->unprocessed.as_bytes + (state->num_bytes % 64), value + i, chunk_size);
        i += chunk_size;
        state->num_bytes += chunk_size;
        if (state->num_bytes % 64 == 0) {
            sha256_internal(state->current_hash, state->unprocessed.as_uint32);
        }
    }
}

void sha256_finish(SHA256_STATE* state, uint8_t hash[32]) {
    int i;
    uint64_t len = state->num_bytes * 8;
    uint8_t one_bit_and_zeros = 0x80;
    sha256_update(state, &one_bit_and_zeros, 1);
    
    int32_t num_zeros_to_add = 56 - (state->num_bytes % 64);
    if (num_zeros_to_add < 0) {
        memset(state->unprocessed.as_bytes + state->num_bytes % 64, 0, 64 - state->num_bytes % 64);
        sha256_internal(state->current_hash, state->unprocessed.as_uint32);
        state->num_bytes += 64 - state->num_bytes % 64;
        num_zeros_to_add = 56;
    }
    
    memset(state->unprocessed.as_bytes + state->num_bytes % 64, 0, num_zeros_to_add);
    state->num_bytes += num_zeros_to_add;
    
    
#if IS_LITTLE_ENDIAN_CPU
    len = REV64(len);
#endif
    sha256_update(state, (uint8_t*)&len, 8);
#if IS_LITTLE_ENDIAN_CPU
    for (i = 0; i < 8; i++) {
        uint32_t t = REV32(state->current_hash[i]);
        memcpy(hash + i * 4, &t, 4);
    }
#else
    memcpy(hash, state->current_hash, 32);
#endif
}

// Note: key_len must be <= 64
void HMACSHA256(const uint8_t* key, size_t key_len, const uint8_t* message, size_t msg_len, uint8_t out[32]) {
    SHA256_STATE ctx;
     
    sha256_init(&ctx);
    memcpy(ctx.unprocessed.as_bytes, key, key_len);
    memset(ctx.unprocessed.as_bytes + key_len, 0, 64 - key_len);
    for(int i = 0; i < 64; i += 4) {
        ctx.unprocessed.as_uint32[i / 4] ^= 0x36363636;
    }
    sha256_internal(ctx.current_hash, ctx.unprocessed.as_uint32);
    ctx.num_bytes = 64;
    sha256_update(&ctx, message, msg_len);
    uint8_t inner_hash[32]; // could use out to save stack
    sha256_finish(&ctx, inner_hash);
     
    sha256_init(&ctx);
    memcpy(ctx.unprocessed.as_bytes, key, key_len);
    memset(ctx.unprocessed.as_bytes + key_len, 0, 64 - key_len);
    for(int i = 0; i < 64; i += 4) {
        ctx.unprocessed.as_uint32[i / 4] ^= 0x5c5c5c5c;
    }
    sha256_internal(ctx.current_hash, ctx.unprocessed.as_uint32);
    ctx.num_bytes = 64;
    sha256_update(&ctx, inner_hash, 32);
    sha256_finish(&ctx, out);
}


void chaskey_generate_subkeys(uint32_t k[12], const uint8_t key[16]) {
    uint32_t v[4];
    v[0] = load_int(key);
    v[1] = load_int(key + 4);
    v[2] = load_int(key + 8);
    v[3] = load_int(key + 12);
    memcpy(k, v, 16);

    uint32_t c = (v[3] >> 31) * 0x87;
    v[3] = (v[3] << 1) | (v[2] >> 31);
    v[2] = (v[2] << 1) | (v[1] >> 31);
    v[1] = (v[1] << 1) | (v[0] >> 31);
    v[0] = (v[0] << 1) ^ c;
    memcpy(k + 4, v, 16);

    c = (v[3] >> 31) * 0x87;
    v[3] = (v[3] << 1) | (v[2] >> 31);
    v[2] = (v[2] << 1) | (v[1] >> 31);
    v[1] = (v[1] << 1) | (v[0] >> 31);
    v[0] = (v[0] << 1) ^ c;
    memcpy(k + 8, v, 16);
}

#define ROR32(a, cnt) ( ((a) >> (cnt)) | ((a) << (32 - (cnt))) )

static void chaskey_permute(uint32_t v[4]) {
    uint32_t r4 = v[0], r5 = v[1], r6 = v[2], r7 = v[3];
    r6 = ROR32(r6, 16);
    for (int i = 0; i < 16; i++) {
        r4 = r4 + r5;
        r5 = r4 ^ ROR32(r5, 27);
        r6 = r7 + ROR32(r6, 16);
        r7 = r6 ^ ROR32(r7, 24);
        r6 = r6 + r5;
        r4 = r7 + ROR32(r4, 16);
        r5 = r6 ^ ROR32(r5, 25);
        r7 = r4 ^ ROR32(r7, 19);
    }
    r6 = ROR32(r6, 16);
    v[0] = r4;
    v[1] = r5;
    v[2] = r6;
    v[3] = r7;
}

void chaskey_with_dir_and_packet_counter(uint8_t out[5], uint32_t keys[12], int dir, uint64_t counter, const uint8_t* data, uint32_t len) {
    uint32_t v[4];
    memcpy(v, keys, 16);
    keys += 4;
    v[0] ^= (uint32_t)counter;
    v[1] ^= (uint32_t)(counter >> 32);
    v[2] ^= dir;
    chaskey_permute(v);

    while (len > 16) {
        v[0] ^= load_int(data);
        v[1] ^= load_int(data + 4);
        v[2] ^= load_int(data + 8);
        v[3] ^= load_int(data + 12);
        data += 16;
        len -= 16;
        chaskey_permute(v);
    }

    if (len < 16) {
        uint8_t tmp[16];
        memcpy(tmp, data, len);
        tmp[len] = 0x01;
        memset(tmp + len + 1, 0, 16 - len - 1);
        v[0] ^= load_int(tmp);
        v[1] ^= load_int(tmp + 4);
        v[2] ^= load_int(tmp + 8);
        v[3] ^= load_int(tmp + 12);
        keys += 4;
    } else {
        v[0] ^= load_int(data);
        v[1] ^= load_int(data + 4);
        v[2] ^= load_int(data + 8);
        v[3] ^= load_int(data + 12);
    }
    v[0] ^= keys[0];
    v[1] ^= keys[1];
    v[2] ^= keys[2];
    v[3] ^= keys[3];
    chaskey_permute(v);
    v[0] ^= keys[0];
    v[1] ^= keys[1];
    out[0] = v[0];
    out[1] = v[0] >> 8;
    out[2] = v[0] >> 16;
    out[3] = v[0] >> 24;
    out[4] = v[1];
}

void chaskey_16_bytes(uint32_t out[4], const uint32_t *keys, const uint32_t data[4]) {
    uint32_t v[4];
    v[0] = keys[0] ^ keys[4] ^ data[0];
    v[1] = keys[1] ^ keys[5] ^ data[1];
    v[2] = keys[2] ^ keys[6] ^ data[2];
    v[3] = keys[3] ^ keys[7] ^ data[3];

    chaskey_permute(v);

    v[0] ^= keys[4];
    v[1] ^= keys[5];
    v[2] ^= keys[6];
    v[3] ^= keys[7];

    out[0] = v[0];
    out[1] = v[1];
    out[2] = v[2];
    out[3] = v[3];
}
