// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IAuth} from "chronicle-std/auth/IAuth.sol";

import {IUScribe} from "../src/IUScribe.sol";
import {UScribe} from "../src/UScribe.sol";

import {UScribeRouter} from "../src/UScribeRouter.sol";

import {DummyConsumer} from "./DummyConsumer.sol";

contract UScribeRouterTest is Test {
    event UScribeUpdated(
        address indexed caller, address oldUScribe, address newUScribe
    );

    DummyRouter public router;
    DummyConsumer public consumer;

    function setUp() public {
        router = new DummyRouter(address(this));
        consumer = new DummyConsumer(address(router), bytes32("VA::DUMMY"));
    }

    //--------------------------------------------------------------------------
    // Test: Set UScribe

    function test_setUScribe() public {
        // Set the UScribe address and expect an emit.
        address uscribe = address(consumer);
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, "VA::DUMMY");

        // Ensure the UScribe address is set correctly.
        assertEq(router.uscribe(), uscribe);

        // Ensure the previous uscribe address field updates.
        consumer = new DummyConsumer(address(router), bytes32("VA::DUMMY"));
        vm.expectEmit();
        emit UScribeUpdated(address(this), uscribe, address(consumer));
        uscribe = address(consumer);
        router.setUScribe(uscribe, "VA::DUMMY");
        assertEq(router.uscribe(), uscribe);
    }

    function test_setUScribe_isIdempotent() public {
        // Set the UScribe address.
        address uscribe = address(consumer);
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, "VA::DUMMY");

        // Expect no emit.
        vm.recordLogs();
        router.setUScribe(uscribe, "VA::DUMMY");
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_setUScribe_RevertsIf_WatMismatch() public {
        // Set the UScribe address.
        address uscribe = address(consumer);
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, "VA::DUMMY");

        // Expect revert if wat does not match.
        vm.expectRevert();
        // Use a different wat.
        router.setUScribe(uscribe, "VA::DUMMY2");
    }

    //--------------------------------------------------------------------------
    // Test: Getters

    function test_getUScribe() public {
        // Check the UScribe address is initially zero.
        assertEq(router.uscribe(), address(0));

        // Set the UScribe address.
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), address(consumer));
        router.setUScribe(address(consumer), "VA::DUMMY");

        // Ensure the UScribe address is set correctly.
        assertEq(router.uscribe(), address(consumer));
    }

    //--------------------------------------------------------------------------
    // Test: Auth Protected Functions

    function test_setUScribe_isAuthProtected() public {
        vm.prank(address(0xbeef));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAuth.NotAuthorized.selector, address(0xbeef)
            )
        );
        router.setUScribe(address(consumer), "VA::DUMMY");
    }
}

contract DummyRouter is UScribeRouter {
    constructor(address initialAuthed) UScribeRouter(initialAuthed) {}
}
