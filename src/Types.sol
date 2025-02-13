// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

struct UPokeData {
    bytes payload;
    string proofURI;
}

struct SchnorrData {
    bytes32 signature;
    address commitment;
    bytes validatorIds;
}

struct ECDSAData {
    uint8 v;
    bytes32 r;
    bytes32 s;
}
