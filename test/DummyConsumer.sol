// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UScribe} from "../src/UScribe.sol";

contract DummyConsumer is UScribe {
    event Poked(bytes payload);

    bool public rejectPokes;

    constructor(address initialAuthed, bytes32 wat)
        UScribe(initialAuthed, wat)
    {}

    function _poke(bytes calldata payload)
        internal
        override(UScribe)
        returns (bytes4)
    {
        if (rejectPokes) {
            return hex"FFFFFFFF";
        }

        emit Poked(payload);
        return _NO_ERR;
    }

    function setRejectPokes(bool to) public {
        rejectPokes = to;
    }
}
