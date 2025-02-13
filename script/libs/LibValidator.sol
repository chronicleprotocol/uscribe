// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {UPokeData, SchnorrData, ECDSAData} from "../../src/Types.sol";
import {LibSecp256k1} from "../../src/libs/LibSecp256k1.sol";

import {LibSchnorrExtended} from "./LibSchnorrExtended.sol";

/// @notice Type validator represents a Chronicle Protocol validator.
struct Validator {
    uint _privKey;
}

/**
 * @title LibValidator
 *
 * @notice Library providing validator functionality.
 */
library LibValidator {
    using LibSchnorrExtended for uint;
    using LibSchnorrExtended for uint[];
    using LibValidator for Validator;
    using LibValidator for address;

    //--------------------------------------------------------------------------
    // Private Constants

    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    //--------------------------------------------------------------------------
    // Construction

    /// @dev Constructs a new validator from string seed `seed`.
    function newValidator(string memory seed)
        internal
        returns (Validator memory)
    {
        Vm.Wallet memory w = vm.createWallet(seed);

        return Validator(w.privateKey);
    }

    /// @dev Constructs a new validator from private key `privKey`.
    ///
    /// @dev Reverts if:
    ///      - private key invalid
    function newValidator(uint privKey)
        internal
        pure
        returns (Validator memory)
    {
        require(
            privKey != 0 && privKey < LibSecp256k1.Q(),
            "LibValidator::newValidator: private key invalid"
        );

        return Validator(privKey);
    }

    /// @dev Returns a list of validators encoded in bloom `bloom`.
    ///
    /// @dev This function can be used to generate pseudo-random validator sets
    ///      by receiving bloom `bloom` as fuzzer argument.
    function newValidatorsFromBloom(uint bloom)
        internal
        pure
        returns (Validator[] memory)
    {
        Validator[] memory all = _all();

        Validator[] memory validators = new Validator[](256);
        uint ctr;
        for (uint i; i < 256; i++) {
            if (bloom & (1 << i) != 0) {
                validators[ctr++] = all[i];
            }
        }

        assembly ("memory-safe") {
            mstore(validators, ctr)
        }

        return validators;
    }

    //--------------------------------------------------------------------------
    // Identity

    /// @dev Returns the validator `self`'s public key.
    function toPublicKey(Validator memory self)
        internal
        returns (LibSecp256k1.Point memory)
    {
        Vm.Wallet memory w = vm.createWallet(self._privKey);

        return LibSecp256k1.Point(w.publicKeyX, w.publicKeyY);
    }

    /// @dev Returns the validator `self`'s address.
    function toAddress(Validator memory self) internal returns (address) {
        return vm.createWallet(self._privKey).addr;
    }

    /// @dev Returns the validator `self`'s id.
    function toId(Validator memory self) internal returns (uint8) {
        return uint8(uint(uint160(self.toAddress())) >> 152);
    }

    //--------------------------------------------------------------------------
    // Signature Generation

    function signSchnorr(Validator memory self, bytes32 message)
        internal
        returns (SchnorrData memory)
    {
        (uint signature, address commitment) =
            self._privKey.signMessage(message);

        return SchnorrData({
            signature: bytes32(signature),
            commitment: commitment,
            validatorIds: abi.encodePacked(self.toId())
        });
    }

    function signSchnorr(Validator[] memory selfs, bytes32 message)
        internal
        returns (SchnorrData memory)
    {
        // IMPORTANT: Verify that
        //
        //      ∀x ∊ [0, selfs.length): sum(selfs[0..x-1]._privKey) != selfs[x]._privKey
        //
        // Otherwise the aggregated public key up to selfs[x-1] will equal the
        // public key of selfs[x]. This will lead to doubling the public key in
        // the next step of the aggregation. However, note that LibSecp256k1's
        // addAffinePoint() function only supports adding different points,
        // ie the implemented addition formula is not complete.
        //
        // Note that it has negligible probablity of such a case to occur if
        // private keys are generated cryptographically secure.
        // However, private keys used during testing are _not_ generated
        // securely leading to the probability of this situation occuring being
        // substantially higher.
        //
        // In order to not fail the test case vm.assume() is used.
        uint accumulator = selfs[0]._privKey;
        for (uint i = 1; i < selfs.length; i++) {
            vm.assume(accumulator != selfs[i]._privKey);
            accumulator += selfs[i]._privKey;
        }

        // Create Schnorr musig.
        uint[] memory privKeys = new uint[](selfs.length);
        for (uint i; i < selfs.length; i++) {
            privKeys[i] = selfs[i]._privKey;
        }
        (uint signature, address commitment) = privKeys.signMessage(message);

        // Create blob of validatorsIds.
        bytes memory validatorIds;
        for (uint i; i < selfs.length; i++) {
            validatorIds = abi.encodePacked(validatorIds, selfs[i].toId());
        }

        return SchnorrData({
            signature: bytes32(signature),
            commitment: commitment,
            validatorIds: validatorIds
        });
    }

    /// @dev Returns an ECDSA signature from validator `self` for given message
    ///      `message`.
    function signECDSA(Validator memory self, bytes32 message)
        internal
        pure
        returns (ECDSAData memory)
    {
        // Sign message via ECDSA.
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(self._privKey, message);

        // Return as ECDSAData.
        return ECDSAData(v, r, s);
    }

    //--------------------------------------------------------------------------
    // Private

    function _all() private pure returns (Validator[] memory) {
        Validator[] memory validators = new Validator[](256);

        // Populate the validator array based on the validator's id.
        //
        // In order to compute the validator list dynamically, do:
        //
        // ```solidity
        // uint privKey = 2;
        // uint bloom;
        // uint ctr;
        // while (ctr != 256) {
        //     Validator memory v = LibValidator.newValidator(privKey);
        //     uint8 id = v.toId();
        //
        //     if (bloom & (1 << id) == 0) {
        //         bloom |= 1 << id;
        //
        //         validators[id] = v;
        //         ctr++;
        //     }
        //
        //     privKey++;
        // }
        // ```
        //
        // In order to verify the list, do:
        //
        // ```solidity
        // for (uint i = 1; i < 256; i++) {
        //     require(validators[i - 1].toId() < validators[i].toId());
        // }
        // ```
        validators[0] = LibValidator.newValidator(130);
        validators[1] = LibValidator.newValidator(296);
        validators[2] = LibValidator.newValidator(536);
        validators[3] = LibValidator.newValidator(254);
        validators[4] = LibValidator.newValidator(104);
        validators[5] = LibValidator.newValidator(111);
        validators[6] = LibValidator.newValidator(512);
        validators[7] = LibValidator.newValidator(171);
        validators[8] = LibValidator.newValidator(372);
        validators[9] = LibValidator.newValidator(33);
        validators[10] = LibValidator.newValidator(193);
        validators[11] = LibValidator.newValidator(80);
        validators[12] = LibValidator.newValidator(105);
        validators[13] = LibValidator.newValidator(133);
        validators[14] = LibValidator.newValidator(113);
        validators[15] = LibValidator.newValidator(671);
        validators[16] = LibValidator.newValidator(400);
        validators[17] = LibValidator.newValidator(227);
        validators[18] = LibValidator.newValidator(79);
        validators[19] = LibValidator.newValidator(34);
        validators[20] = LibValidator.newValidator(263);
        validators[21] = LibValidator.newValidator(21);
        validators[22] = LibValidator.newValidator(230);
        validators[23] = LibValidator.newValidator(118);
        validators[24] = LibValidator.newValidator(160);
        validators[25] = LibValidator.newValidator(638);
        validators[26] = LibValidator.newValidator(76);
        validators[27] = LibValidator.newValidator(338);
        validators[28] = LibValidator.newValidator(211);
        validators[29] = LibValidator.newValidator(27);
        validators[30] = LibValidator.newValidator(4);
        validators[31] = LibValidator.newValidator(1028);
        validators[32] = LibValidator.newValidator(157);
        validators[33] = LibValidator.newValidator(143);
        validators[34] = LibValidator.newValidator(270);
        validators[35] = LibValidator.newValidator(353);
        validators[36] = LibValidator.newValidator(99);
        validators[37] = LibValidator.newValidator(17);
        validators[38] = LibValidator.newValidator(212);
        validators[39] = LibValidator.newValidator(150);
        validators[40] = LibValidator.newValidator(89);
        validators[41] = LibValidator.newValidator(336);
        validators[42] = LibValidator.newValidator(117);
        validators[43] = LibValidator.newValidator(2);
        validators[44] = LibValidator.newValidator(307);
        validators[45] = LibValidator.newValidator(348);
        validators[46] = LibValidator.newValidator(191);
        validators[47] = LibValidator.newValidator(334);
        validators[48] = LibValidator.newValidator(844);
        validators[49] = LibValidator.newValidator(186);
        validators[50] = LibValidator.newValidator(32);
        validators[51] = LibValidator.newValidator(452);
        validators[52] = LibValidator.newValidator(500);
        validators[53] = LibValidator.newValidator(301);
        validators[54] = LibValidator.newValidator(59);
        validators[55] = LibValidator.newValidator(22);
        validators[56] = LibValidator.newValidator(204);
        validators[57] = LibValidator.newValidator(967);
        validators[58] = LibValidator.newValidator(287);
        validators[59] = LibValidator.newValidator(23);
        validators[60] = LibValidator.newValidator(190);
        validators[61] = LibValidator.newValidator(11);
        validators[62] = LibValidator.newValidator(406);
        validators[63] = LibValidator.newValidator(216);
        validators[64] = LibValidator.newValidator(365);
        validators[65] = LibValidator.newValidator(106);
        validators[66] = LibValidator.newValidator(175);
        validators[67] = LibValidator.newValidator(916);
        validators[68] = LibValidator.newValidator(97);
        validators[69] = LibValidator.newValidator(205);
        validators[70] = LibValidator.newValidator(385);
        validators[71] = LibValidator.newValidator(291);
        validators[72] = LibValidator.newValidator(538);
        validators[73] = LibValidator.newValidator(836);
        validators[74] = LibValidator.newValidator(29);
        validators[75] = LibValidator.newValidator(19);
        validators[76] = LibValidator.newValidator(10);
        validators[77] = LibValidator.newValidator(67);
        validators[78] = LibValidator.newValidator(288);
        validators[79] = LibValidator.newValidator(234);
        validators[80] = LibValidator.newValidator(255);
        validators[81] = LibValidator.newValidator(173);
        validators[82] = LibValidator.newValidator(625);
        validators[83] = LibValidator.newValidator(200);
        validators[84] = LibValidator.newValidator(491);
        validators[85] = LibValidator.newValidator(197);
        validators[86] = LibValidator.newValidator(357);
        validators[87] = LibValidator.newValidator(292);
        validators[88] = LibValidator.newValidator(119);
        validators[89] = LibValidator.newValidator(207);
        validators[90] = LibValidator.newValidator(14);
        validators[91] = LibValidator.newValidator(373);
        validators[92] = LibValidator.newValidator(85);
        validators[93] = LibValidator.newValidator(343);
        validators[94] = LibValidator.newValidator(322);
        validators[95] = LibValidator.newValidator(148);
        validators[96] = LibValidator.newValidator(225);
        validators[97] = LibValidator.newValidator(115);
        validators[98] = LibValidator.newValidator(549);
        validators[99] = LibValidator.newValidator(28);
        validators[100] = LibValidator.newValidator(146);
        validators[101] = LibValidator.newValidator(1011);
        validators[102] = LibValidator.newValidator(1133);
        validators[103] = LibValidator.newValidator(48);
        validators[104] = LibValidator.newValidator(3);
        validators[105] = LibValidator.newValidator(135);
        validators[106] = LibValidator.newValidator(825);
        validators[107] = LibValidator.newValidator(31);
        validators[108] = LibValidator.newValidator(45);
        validators[109] = LibValidator.newValidator(308);
        validators[110] = LibValidator.newValidator(326);
        validators[111] = LibValidator.newValidator(66);
        validators[112] = LibValidator.newValidator(269);
        validators[113] = LibValidator.newValidator(273);
        validators[114] = LibValidator.newValidator(103);
        validators[115] = LibValidator.newValidator(237);
        validators[116] = LibValidator.newValidator(241);
        validators[117] = LibValidator.newValidator(65);
        validators[118] = LibValidator.newValidator(647);
        validators[119] = LibValidator.newValidator(670);
        validators[120] = LibValidator.newValidator(390);
        validators[121] = LibValidator.newValidator(18);
        validators[122] = LibValidator.newValidator(71);
        validators[123] = LibValidator.newValidator(91);
        validators[124] = LibValidator.newValidator(217);
        validators[125] = LibValidator.newValidator(35);
        validators[126] = LibValidator.newValidator(154);
        validators[127] = LibValidator.newValidator(279);
        validators[128] = LibValidator.newValidator(90);
        validators[129] = LibValidator.newValidator(20);
        validators[130] = LibValidator.newValidator(903);
        validators[131] = LibValidator.newValidator(139);
        validators[132] = LibValidator.newValidator(86);
        validators[133] = LibValidator.newValidator(73);
        validators[134] = LibValidator.newValidator(243);
        validators[135] = LibValidator.newValidator(15);
        validators[136] = LibValidator.newValidator(78);
        validators[137] = LibValidator.newValidator(702);
        validators[138] = LibValidator.newValidator(320);
        validators[139] = LibValidator.newValidator(412);
        validators[140] = LibValidator.newValidator(432);
        validators[141] = LibValidator.newValidator(112);
        validators[142] = LibValidator.newValidator(184);
        validators[143] = LibValidator.newValidator(487);
        validators[144] = LibValidator.newValidator(252);
        validators[145] = LibValidator.newValidator(878);
        validators[146] = LibValidator.newValidator(108);
        validators[147] = LibValidator.newValidator(36);
        validators[148] = LibValidator.newValidator(174);
        validators[149] = LibValidator.newValidator(540);
        validators[150] = LibValidator.newValidator(865);
        validators[151] = LibValidator.newValidator(1238);
        validators[152] = LibValidator.newValidator(496);
        validators[153] = LibValidator.newValidator(95);
        validators[154] = LibValidator.newValidator(25);
        validators[155] = LibValidator.newValidator(136);
        validators[156] = LibValidator.newValidator(819);
        validators[157] = LibValidator.newValidator(657);
        validators[158] = LibValidator.newValidator(44);
        validators[159] = LibValidator.newValidator(790);
        validators[160] = LibValidator.newValidator(121);
        validators[161] = LibValidator.newValidator(55);
        validators[162] = LibValidator.newValidator(137);
        validators[163] = LibValidator.newValidator(56);
        validators[164] = LibValidator.newValidator(141);
        validators[165] = LibValidator.newValidator(30);
        validators[166] = LibValidator.newValidator(823);
        validators[167] = LibValidator.newValidator(93);
        validators[168] = LibValidator.newValidator(249);
        validators[169] = LibValidator.newValidator(72);
        validators[170] = LibValidator.newValidator(379);
        validators[171] = LibValidator.newValidator(570);
        validators[172] = LibValidator.newValidator(83);
        validators[173] = LibValidator.newValidator(299);
        validators[174] = LibValidator.newValidator(42);
        validators[175] = LibValidator.newValidator(81);
        validators[176] = LibValidator.newValidator(68);
        validators[177] = LibValidator.newValidator(74);
        validators[178] = LibValidator.newValidator(606);
        validators[179] = LibValidator.newValidator(127);
        validators[180] = LibValidator.newValidator(572);
        validators[181] = LibValidator.newValidator(38);
        validators[182] = LibValidator.newValidator(394);
        validators[183] = LibValidator.newValidator(309);
        validators[184] = LibValidator.newValidator(46);
        validators[185] = LibValidator.newValidator(110);
        validators[186] = LibValidator.newValidator(235);
        validators[187] = LibValidator.newValidator(476);
        validators[188] = LibValidator.newValidator(321);
        validators[189] = LibValidator.newValidator(313);
        validators[190] = LibValidator.newValidator(679);
        validators[191] = LibValidator.newValidator(488);
        validators[192] = LibValidator.newValidator(242);
        validators[193] = LibValidator.newValidator(297);
        validators[194] = LibValidator.newValidator(77);
        validators[195] = LibValidator.newValidator(26);
        validators[196] = LibValidator.newValidator(219);
        validators[197] = LibValidator.newValidator(490);
        validators[198] = LibValidator.newValidator(128);
        validators[199] = LibValidator.newValidator(419);
        validators[200] = LibValidator.newValidator(374);
        validators[201] = LibValidator.newValidator(691);
        validators[202] = LibValidator.newValidator(483);
        validators[203] = LibValidator.newValidator(813);
        validators[204] = LibValidator.newValidator(608);
        validators[205] = LibValidator.newValidator(192);
        validators[206] = LibValidator.newValidator(415);
        validators[207] = LibValidator.newValidator(94);
        validators[208] = LibValidator.newValidator(129);
        validators[209] = LibValidator.newValidator(413);
        validators[210] = LibValidator.newValidator(161);
        validators[211] = LibValidator.newValidator(305);
        validators[212] = LibValidator.newValidator(7);
        validators[213] = LibValidator.newValidator(203);
        validators[214] = LibValidator.newValidator(107);
        validators[215] = LibValidator.newValidator(319);
        validators[216] = LibValidator.newValidator(37);
        validators[217] = LibValidator.newValidator(100);
        validators[218] = LibValidator.newValidator(293);
        validators[219] = LibValidator.newValidator(12);
        validators[220] = LibValidator.newValidator(654);
        validators[221] = LibValidator.newValidator(151);
        validators[222] = LibValidator.newValidator(134);
        validators[223] = LibValidator.newValidator(315);
        validators[224] = LibValidator.newValidator(64);
        validators[225] = LibValidator.newValidator(5);
        validators[226] = LibValidator.newValidator(168);
        validators[227] = LibValidator.newValidator(637);
        validators[228] = LibValidator.newValidator(947);
        validators[229] = LibValidator.newValidator(6);
        validators[230] = LibValidator.newValidator(53);
        validators[231] = LibValidator.newValidator(448);
        validators[232] = LibValidator.newValidator(125);
        validators[233] = LibValidator.newValidator(1240);
        validators[234] = LibValidator.newValidator(364);
        validators[235] = LibValidator.newValidator(43);
        validators[236] = LibValidator.newValidator(1216);
        validators[237] = LibValidator.newValidator(595);
        validators[238] = LibValidator.newValidator(156);
        validators[239] = LibValidator.newValidator(437);
        validators[240] = LibValidator.newValidator(224);
        validators[241] = LibValidator.newValidator(8);
        validators[242] = LibValidator.newValidator(41);
        validators[243] = LibValidator.newValidator(155);
        validators[244] = LibValidator.newValidator(24);
        validators[245] = LibValidator.newValidator(131);
        validators[246] = LibValidator.newValidator(39);
        validators[247] = LibValidator.newValidator(9);
        validators[248] = LibValidator.newValidator(386);
        validators[249] = LibValidator.newValidator(57);
        validators[250] = LibValidator.newValidator(16);
        validators[251] = LibValidator.newValidator(114);
        validators[252] = LibValidator.newValidator(220);
        validators[253] = LibValidator.newValidator(271);
        validators[254] = LibValidator.newValidator(84);
        validators[255] = LibValidator.newValidator(75);

        return validators;
    }
}
