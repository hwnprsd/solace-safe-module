// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.19;

import "./SigManager.sol";
import "./Safe.sol";
import "./Enum.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SolaceSafeModule is SigManager {
    using ECDSA for bytes32;

    struct SolaceTx {
        address tokenAddress;
        address to;
        uint256 value;
    }

    function getTransferCalldata(
        SolaceTx memory solaceTx
    ) public pure returns (bytes memory) {
        // Function signature for ERC20 transfer function
        string memory functionSignature = "transfer(address,uint256)";

        // Compute the function selector
        bytes4 selector = bytes4(keccak256(bytes(functionSignature)));

        // Generate calldata
        bytes memory data = abi.encodeWithSelector(
            selector,
            solaceTx.to,
            solaceTx.value
        );

        return data;
    }

    function getMessageHash(
        SolaceTx memory solaceTx
    ) public view returns (bytes32) {
        // Hash the SolaceTx struct
        bytes32 txHash = keccak256(
            abi.encode(
                getChainId(),
                solaceTx.tokenAddress,
                solaceTx.to,
                solaceTx.value
            )
        );

        // Create the Ethereum signed message hash using OpenZeppelin's toEthSignedMessageHash
        bytes32 ethSignedMessageHash = txHash.toEthSignedMessageHash();

        return ethSignedMessageHash;
    }

    function transfer(address safe, SolaceTx calldata solaceTx) private {
        bytes memory data = new bytes(0);
        uint256 value = solaceTx.value;
        address to = solaceTx.to;
        if (solaceTx.tokenAddress != address(0)) {
            data = getTransferCalldata(solaceTx);
            value = 0;
            to = solaceTx.tokenAddress;
        }
        require(
            GnosisSafe(safe).execTransactionFromModule(
                to,
                value,
                data,
                Enum.Operation.Call
            ),
            "SGS400"
        );
    }

    // V1 will only support ERC20 & ETH transfers
    function executeTransfer(
        address safe,
        bytes memory solaceSignature,
        SolaceTx calldata solaceTx
    ) external {
        // Check if Safe account is being managed
        require(solaceMapping[safe] != address(0), "SGS000");
        // Check if sender is whitelisted
        require(whitelist[safe][msg.sender] != address(0), "SGS001");
        // Check if the appropriate solace network address has signed the transaction
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Extract r, s, v from the signature
        assembly {
            r := mload(add(solaceSignature, 0x20))
            s := mload(add(solaceSignature, 0x40))
            v := byte(0, mload(add(solaceSignature, 0x60)))
        }
        require(
            ecrecover(getMessageHash(solaceTx), v, r, s) == solaceMapping[safe],
            "SGS200"
        );

        // Construct the transfer and call the execTransactionFromModule function
        transfer(safe, solaceTx);
    }

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }
}
