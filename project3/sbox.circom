pragma circom 2.0.0;

template Pow5() {
    signal input in;
    signal output out;

    // x^5 = x * x * x * x * x
    signal x2; x2 <== in * in;
    signal x3; x3 <== x2 * in;
    signal x4; x4 <== x3 * in;
    out <== x4 * in;
}

component main = Pow5();
