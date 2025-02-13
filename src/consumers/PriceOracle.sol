// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Toll} from "chronicle-std/toll/Toll.sol";

import {UScribe} from "../UScribe.sol";

// TODO: Implement IChronicle interface
contract PriceOracle is UScribe, Toll {
    event Poked(address indexed caller, uint128 val, uint32 age);

    uint128 internal _val;
    uint32 internal _age;

    constructor(address initialAuthed, bytes32 wat)
        UScribe(initialAuthed, wat)
    {}

    function _poke(bytes calldata payload)
        internal
        override(UScribe)
        returns (bytes4)
    {
        // Fail if payload not exactly two words.
        if (payload.length != 0x60) {
            return hex"FFFFFFFF";
        }

        // Decode payload into two words.
        (uint word1, uint word2) = abi.decode(payload, (uint, uint));

        // Decode word1 into val.
        uint128 val;
        if (word1 > type(uint128).max) {
            return hex"FFFFFFFF";
        }
        val = uint128(word1);

        // Decode word2 into age.
        uint32 age;
        if (word2 > type(uint32).max) {
            return hex"FFFFFFFF";
        }
        age = uint32(word2);

        // Fail if val stale.
        if (age <= _age) {
            return hex"FFFFFFFF";
        }
        // Fail if val from the future.
        if (age > block.timestamp) {
            return hex"FFFFFFFF";
        }

        // Update state.
        _val = val;
        _age = uint32(block.timestamp);

        emit Poked(msg.sender, val, age);

        return _NO_ERR;
    }

    function toll_auth() internal override(Toll) auth {}
}
