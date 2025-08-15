pragma circom 2.0.0;

include "poseidon2.circom";

template Poseidon2SingleBlock() {
    var t = 3;
    var RF = 8;
    var RP = 8;
    var totalRounds = RF + RP;

    signal input pubHash;
    signal private input preimage[2];


    signal input RC[totalRounds * t];
    signal input MDS[t][t];


    signal stateIn[t];
    stateIn[0] <== 0;
    stateIn[1] <== preimage[0];
    stateIn[2] <== preimage[1];

    component P = PoseidonPerm(t, RF, RP)();
    for (var i = 0; i < totalRounds * t; i++) {
        P.RC[i] <== RC[i];
    }
    for (var i = 0; i < t; i++) {
        for (var j = 0; j < t; j++) {
            P.MDS[i][j] <== MDS[i][j];
        }
    }
    for (var i = 0; i < t; i++) {
        P.stateIn[i] <== stateIn[i];
    }

    signal out0; out0 <== P.stateOut[0];
    pubHash === out0;
}

component main = Poseidon2SingleBlock();