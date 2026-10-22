// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract Store {

    struct StorePoint {
        uint256 id;
        string stringPoint;
    }

    mapping (address=>StorePoint[]) storeView;

    function addString(string memory point)public {
        uint256 id = storeView[msg.sender].length;
        storeView[msg.sender].push(StorePoint(id, point));
    }

    function getAll()public view returns(StorePoint[] memory){
        return storeView[msg.sender];
    }

    function updateStore(uint256 id,string memory updated) public {
        StorePoint storage store = storeView[msg.sender][id];
        store.stringPoint=updated;
    }
}
