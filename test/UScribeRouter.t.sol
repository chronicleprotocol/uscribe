// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IAuth} from "chronicle-std/auth/IAuth.sol";

import {IUScribe} from "../src/IUScribe.sol";
import {UScribe} from "../src/UScribe.sol";

import {UScribeRouter} from "../src/UScribeRouter.sol";

import {DummyConsumer} from "./DummyConsumer.sol";

contract UScribeRouterTest is Test {
    DummyRouter router;
    DummyConsumer consumer;
    string constant NAME = "VA::Test";

    // Events copied from UScribeRouter.
    event UScribeUpdated(
        address indexed caller, address oldUScribe, address newUScribe
    );

    function setUp() public {
        router = new DummyRouter(address(this));
        consumer = new DummyConsumer(address(this), NAME);
    }

    //--------------------------------------------------------------------------
    // Test: Deployment

    function test_Deploymebnts() public view {
        // Only address given during construction is auth'ed.
        assertTrue(router.authed(address(this)));
        assertEq(router.authed().length, 1);

        // UScribe is not set.
        assertEq(router.uscribe(), address(0));
    }

    //--------------------------------------------------------------------------
    // Test: Set UScribe

    function test_setUScribe() public {
        // Set the UScribe address and expect an emit.
        address uscribe1 = address(consumer);
        bytes32 wat1 = consumer.wat();
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe1);
        router.setUScribe(uscribe1, wat1);

        // Expect UScribe address to be set.
        assertEq(router.uscribe(), uscribe1);

        // Set to new UScribe address and expect emit.
        DummyConsumer consumer2 = new DummyConsumer(address(this), "VA::Test2");
        address uscribe2 = address(consumer2);
        bytes32 wat2 = consumer2.wat();
        vm.expectEmit();
        emit UScribeUpdated(address(this), uscribe1, uscribe2);
        router.setUScribe(uscribe2, wat2);

        // Expect new UScribe address to be set.
        assertEq(router.uscribe(), uscribe2);
    }

    function test_setUScribe_isIdempotent() public {
        // Set the UScribe address.
        address uscribe = address(consumer);
        bytes32 wat = consumer.wat();
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, wat);

        // Expect no emit.
        vm.recordLogs();
        router.setUScribe(uscribe, wat);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_setUScribe_RevertsIf_WatMismatch() public {
        // Set the UScribe address.
        address uscribe = address(consumer);
        bytes32 wat = consumer.wat();
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, wat);

        // Expect revert if wat does not match.
        vm.expectRevert();
        router.setUScribe(uscribe, bytes32("not wat"));
    }

    //--------------------------------------------------------------------------
    // Test: Getters

    function test_getUScribe() public {
        // Set the UScribe address.
        address uscribe = address(consumer);
        bytes32 wat = consumer.wat();
        vm.expectEmit();
        emit UScribeUpdated(address(this), address(0), uscribe);
        router.setUScribe(uscribe, wat);

        // Ensure the UScribe address is set correctly.
        assertEq(router.uscribe(), uscribe);
    }

    //--------------------------------------------------------------------------
    // Test: Auth Protected Functions

    function test_setUScribe_isAuthProtected() public {
        address uscribe = address(consumer);
        bytes32 wat = consumer.wat();
        vm.prank(address(0xbeef));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAuth.NotAuthorized.selector, address(0xbeef)
            )
        );
        router.setUScribe(uscribe, wat);
    }
}

contract DummyRouter is UScribeRouter {
    constructor(address initialAuthed) UScribeRouter(initialAuthed) {}
}
