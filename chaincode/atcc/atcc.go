package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

type SeqNumber struct {
	BlockNumber uint64 `json:"BlockNumber"`
	Offset      int    `json:"Offset"`
}

// Asset describes basic details of what makes up a simple asset
type Asset struct {
	ID               string    `json:"ID"`
	SequenceNumber   SeqNumber `json:"SequenceNumber"`
	EndorsementCount int       `json:"EndorsementCount"`
	Status           int       `json:"Status"`
}

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	assets := []Asset{
		{ID: "asset1-0", SequenceNumber: SeqNumber{BlockNumber: 1, Offset: 0}, EndorsementCount: 1, Status: 0},
		{ID: "asset1-1", SequenceNumber: SeqNumber{BlockNumber: 1, Offset: 1}, EndorsementCount: 1, Status: 0},
		{ID: "asset1-2", SequenceNumber: SeqNumber{BlockNumber: 1, Offset: 2}, EndorsementCount: 1, Status: 0},
		{ID: "asset2-0", SequenceNumber: SeqNumber{BlockNumber: 2, Offset: 0}, EndorsementCount: 1, Status: 0},
		{ID: "asset2-1", SequenceNumber: SeqNumber{BlockNumber: 2, Offset: 1}, EndorsementCount: 1, Status: 0},
	}

	for _, asset := range assets {
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(asset.ID, assetJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

func (s *SmartContract) CreateLedger(ctx contractapi.TransactionContextInterface, blockNumber uint64, offset int, endorsementCount int) error {
	id := getId(blockNumber, offset)
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", id)
	}

	sequenceNumber := SeqNumber{BlockNumber: blockNumber, Offset: offset}
	asset := Asset{
		ID:               id,
		SequenceNumber:   sequenceNumber,
		EndorsementCount: 1,
		Status:           0,
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var asset Asset
	err = json.Unmarshal(assetJSON, &asset)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}

func (s *SmartContract) EndorsementInc(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exists", id)
	}

	curAsset, err := s.ReadAsset(ctx, id)
	if err != nil {
		return err
	}

	curAsset.EndorsementCount++
	assetJSON, err := json.Marshal(curAsset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) DeleteAsset(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

func (s *SmartContract) ChangeStatus(ctx contractapi.TransactionContextInterface, id string, status int) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", id)
	}
	curAsset, err := s.ReadAsset(ctx, id)
	if err != nil {
		return err
	}

	curAsset.Status = status
	assetJSON, err := json.Marshal(curAsset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var assets []*Asset
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var asset Asset
		err = json.Unmarshal(queryResponse.Value, &asset)
		if err != nil {
			return nil, err
		}
		assets = append(assets, &asset)
	}

	return assets, nil
}

func getId(blockNumber uint64, offset int) string {
	return "asset" + strconv.FormatUint(blockNumber, 10) + "-" + strconv.Itoa(offset)
}

func main() {
	assetChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating asset-transfer-basic chaincode: %v", err)
	}

	if err := assetChaincode.Start(); err != nil {
		log.Panicf("Error starting asset-transfer-basic chaincode: %v", err)
	}
}
