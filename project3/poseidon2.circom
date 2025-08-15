pragma circom 2.0.0;

include "sbox.circom";

template PoseidonPerm(t, RF, RP) {
    assert(t == 3, "Template expects t=3");
    signal input RC[(RF + RP) * t];
    signal input MDS[t][t];


    signal input stateIn[t];
    signal output stateOut[t];

    signal s0; signal s1; signal s2;
    s0 <== stateIn[0];
    s1 <== stateIn[1];
    s2 <== stateIn[2];

    var rcIdx = 0;
    component mdsMul = null; // placeholder (we'll inline)

    // first RF/2 full rounds
    var halfFull = RF / 2;
    for (var r = 0; r < halfFull; r++) {
        // add RC (t constants)
        s0 <== s0 + RC[rcIdx + 0];
        s1 <== s1 + RC[rcIdx + 1];
        s2 <== s2 + RC[rcIdx + 2];

        // apply S-box to all (x^5)
        component p0 = Pow5();
        component p1 = Pow5();
        component p2 = Pow5();
        p0.in <== s0; p1.in <== s1; p2.in <== s2;
        s0 <== p0.out; s1 <== p1.out; s2 <== p2.out;

        // mix (MDS)
        signal ms0; signal ms1; signal ms2;
        ms0 <== MDS[0][0]*s0 + MDS[0][1]*s1 + MDS[0][2]*s2;
        ms1 <== MDS[1][0]*s0 + MDS[1][1]*s1 + MDS[1][2]*s2;
        ms2 <== MDS[2][0]*s0 + MDS[2][1]*s1 + MDS[2][2]*s2;
        s0 <== ms0; s1 <== ms1; s2 <== ms2;

        rcIdx += t;
    }

    // RP partial rounds
    for (var r = 0; r < RP; r++) {
        // add round constants
        s0 <== s0 + RC[rcIdx + 0];
        s1 <== s1 + RC[rcIdx + 1];
        s2 <== s2 + RC[rcIdx + 2];

        // apply S-box only to first element (partial round)
        component pA = Pow5();
        pA.in <== s0;
        s0 <== pA.out;

        // mix (MDS)
        signal ms0b; signal ms1b; signal ms2b;
        ms0b <== MDS[0][0]*s0 + MDS[0][1]*s1 + MDS[0][2]*s2;
        ms1b <== MDS[1][0]*s0 + MDS[1][1]*s1 + MDS[1][2]*s2;
        ms2b <== MDS[2][0]*s0 + MDS[2][1]*s1 + MDS[2][2]*s2;
        s0 <== ms0b; s1 <== ms1b; s2 <== ms2b;

        rcIdx += t;
    }

    // final RF/2 full rounds
    for (var r = 0; r < halfFull; r++) {
        // add RC
        s0 <== s0 + RC[rcIdx + 0];
        s1 <== s1 + RC[rcIdx + 1];
        s2 <== s2 + RC[rcIdx + 2];

        // sbox all
        component p3 = Pow5();
        component p4 = Pow5();
        component p5 = Pow5();
        p3.in <== s0; p4.in <== s1; p5.in <== s2;
        s0 <== p3.out; s1 <== p4.out; s2 <== p5.out;

        // mix
        signal ms0c; signal ms1c; signal ms2c;
        ms0c <== MDS[0][0]*s0 + MDS[0][1]*s1 + MDS[0][2]*s2;
        ms1c <== MDS[1][0]*s0 + MDS[1][1]*s1 + MDS[1][2]*s2;
        ms2c <== MDS[2][0]*s0 + MDS[2][1]*s1 + MDS[2][2]*s2;
        s0 <== ms0c; s1 <== ms1c; s2 <== ms2c;

        rcIdx += t;
    }

    // output wires
    stateOut[0] <== s0;
    stateOut[1] <== s1;
    stateOut[2] <== s2;
}

component main = PoseidonPerm(3, 8, 8)(); // template instantiation words are placeholders; when including set RF/RP accordingly in compile-time if needed
