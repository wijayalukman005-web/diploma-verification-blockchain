// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract DiplomaVerification is AccessControl {

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    struct Diploma {
        string diplomaId;
        string studentName;
        string institution;
        string degree;
        uint256 issueDate;
        bytes32 documentHash;
        bool revoked;
    }

    mapping(string => Diploma) private diplomas;

    event DiplomaIssued(
        string diplomaId,
        string studentName,
        bytes32 documentHash
    );

    event DiplomaRevoked(string diplomaId);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
    }

    function issueDiploma(
        string memory diplomaId,
        string memory studentName,
        string memory institution,
        string memory degree,
        uint256 issueDate,
        bytes32 documentHash
    ) public onlyRole(ISSUER_ROLE) {

        require(
            diplomas[diplomaId].documentHash == bytes32(0),
            "Diploma already exists"
        );

        diplomas[diplomaId] = Diploma(
            diplomaId,
            studentName,
            institution,
            degree,
            issueDate,
            documentHash,
            false
        );

        emit DiplomaIssued(
            diplomaId,
            studentName,
            documentHash
        );
    }

    function verifyDiploma(
        string memory diplomaId,
        bytes32 documentHash
    ) public view returns (bool) {

        Diploma memory diploma = diplomas[diplomaId];

        return (
            diploma.documentHash == documentHash &&
            !diploma.revoked
        );
    }

    function revokeDiploma(
        string memory diplomaId
    ) public onlyRole(ISSUER_ROLE) {

        require(
            diplomas[diplomaId].documentHash != bytes32(0),
            "Diploma not found"
        );

        diplomas[diplomaId].revoked = true;

        emit DiplomaRevoked(diplomaId);
    }

    function getDiploma(
        string memory diplomaId
    )
        public
        view
        returns (
            string memory,
            string memory,
            string memory,
            string memory,
            uint256,
            bytes32,
            bool
        )
    {
        Diploma memory d = diplomas[diplomaId];

        return (
            d.diplomaId,
            d.studentName,
            d.institution,
            d.degree,
            d.issueDate,
            d.documentHash,
            d.revoked
        );
    }
}
