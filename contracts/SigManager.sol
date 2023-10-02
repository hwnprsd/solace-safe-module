// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.19;
import "./Safe.sol";

contract SigManager {
    address internal constant SENTINEL_INDEX = address(0x1);
    // Mapping of Smart Wallet Address => Solace Address provided by the keynet
    mapping(address => address) solaceMapping;
    // Mapping of Smart Wallet Addresses to the whitelist of address allowed to interact with the module
    mapping(address => mapping(address => address)) whitelist;

    function validateOwner(
        address sender,
        address safe
    ) internal view returns (bool) {
        // TODO: Implement multisig rules to ensure
        return GnosisSafe(safe).isOwner(sender);
    }

    // Set or override solace address
    function setSolaceAddress(address safe, address solace) external {
        require(safe != address(0) && solace != address(0), "SGS100");
        require(validateOwner(msg.sender, safe), "SGS101");
        solaceMapping[safe] = solace;
    }

    function setWhitelist(address safe, address[] memory _whitelist) external {
        require(safe != address(0), "SGS100");
        require(validateOwner(msg.sender, safe), "SGS101");
        address curr = SENTINEL_INDEX;
        for (uint256 i = 0; i < _whitelist.length; i++) {
            address toWhitelist = _whitelist[i];
            require(
                toWhitelist != address(0) &&
                    toWhitelist != SENTINEL_INDEX &&
                    curr != toWhitelist,
                "SGS102"
            );
            require(whitelist[safe][toWhitelist] == address(0), "SGS103");
            whitelist[safe][curr] = toWhitelist;
            curr = toWhitelist;
        }
        whitelist[safe][curr] = SENTINEL_INDEX;
    }

    function addWhitelistedAddress(address safe, address toWhitelist) external {
        require(safe != address(0), "SGS100");
        require(validateOwner(msg.sender, safe), "SGS101");
        require(whitelist[safe][toWhitelist] == address(0), "SGS103");
        require(
            toWhitelist != address(0) && toWhitelist != SENTINEL_INDEX,
            "SGS104"
        );
        whitelist[safe][toWhitelist] = whitelist[safe][SENTINEL_INDEX];
        whitelist[safe][SENTINEL_INDEX] = toWhitelist;
    }

    function removeWhitelistedAddress(
        address safe,
        address prevWhitelistAddr,
        address toRemove
    ) external {
        require(safe != address(0), "SGS100");
        require(validateOwner(msg.sender, safe), "SGS101");
        require(toRemove != address(0) && toRemove != SENTINEL_INDEX, "SGS104");
        require(whitelist[safe][prevWhitelistAddr] == toRemove, "SGS105");
        whitelist[safe][prevWhitelistAddr] = whitelist[safe][toRemove];
        whitelist[safe][toRemove] = address(0);
    }
}
