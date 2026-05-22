// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ThreatLogger {
    struct Threat {
        uint256 id;
        string entityType;
        string value;
        string description;
        string severity;
        uint256 timestamp;
        address reporter;
    }

    // Mapping from threat ID to Threat record
    mapping(uint256 => Threat) private threats;
    
    // Counter for total threats
    uint256 public threatCount;

    // Events
    event ThreatAdded(
        uint256 indexed id,
        string entityType,
        string indexed value,
        string severity,
        uint256 timestamp,
        address indexed reporter
    );

    /**
     * @dev Stores a new threat log on the blockchain.
     * @param _entityType The type of threat (e.g., "wallet", "domain", "contract").
     * @param _value The actual indicator of compromise (e.g., address, domain name).
     * @param _description Descriptive context about the threat.
     * @param _severity Severity level (e.g., "Low Risk", "Medium Risk", "High Risk", "Critical").
     * @return The ID of the newly created threat record.
     */
    function addThreat(
        string calldata _entityType,
        string calldata _value,
        string calldata _description,
        string calldata _severity
    ) public returns (uint256) {
        require(bytes(_value).length > 0, "Threat value cannot be empty");
        
        threatCount++;
        
        threats[threatCount] = Threat({
            id: threatCount,
            entityType: _entityType,
            value: _value,
            description: _description,
            severity: _severity,
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        emit ThreatAdded(
            threatCount,
            _entityType,
            _value,
            _severity,
            block.timestamp,
            msg.sender
        );

        return threatCount;
    }

    /**
     * @dev Retrieves threat details by ID.
     * @param _id The ID of the threat record.
     */
    function getThreat(uint256 _id)
        public
        view
        returns (
            uint256 id,
            string memory entityType,
            string memory value,
            string memory description,
            string memory severity,
            uint256 timestamp,
            address reporter
        )
    {
        require(_id > 0 && _id <= threatCount, "Threat ID does not exist");
        Threat storage threat = threats[_id];
        return (
            threat.id,
            threat.entityType,
            threat.value,
            threat.description,
            threat.severity,
            threat.timestamp,
            threat.reporter
        );
    }

    /**
     * @dev Verifies threat record matches the provided value.
     * @param _id The ID of the threat record.
     * @param _value The value to check against (e.g., matching address).
     */
    function verifyThreat(uint256 _id, string calldata _value)
        public
        view
        returns (bool)
    {
        if (_id == 0 || _id > threatCount) {
            return false;
        }
        return keccak256(bytes(threats[_id].value)) == keccak256(bytes(_value));
    }
}
