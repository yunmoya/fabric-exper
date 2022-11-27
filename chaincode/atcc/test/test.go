package main

import (
	"fmt"
	"strconv"
	"encoding/json"
)

type SeqNumber struct{
	BlockNumber uint64 `json:"BlockNumber"`
	Offset int `json:"Offset"`
}

type Asset struct {
	SequenceNumber SeqNumber `json:"SequenceNumber"`
	EndorsementCount int `json:"EndorsementCount"`
	ID string `json:"ID"`
}

func main() {
	blockNumber := uint64(11111)
	offset := 2
	id := getId(blockNumber, offset);
	fmt.Println(id)
	sequenceNumber := SeqNumber{BlockNumber: blockNumber, Offset: offset}
	asset := Asset{
		ID: id,
		SequenceNumber: sequenceNumber,
		EndorsementCount: 1,
	}
	result, _:= json.Marshal(asset)
	fmt.Println(string(result))
	asset.EndorsementCount ++
	result, _ = json.Marshal(asset)
	fmt.Println(string(result))
}

func getId(blockNumber uint64, offset int) string {
	return "asset" + strconv.FormatUint(blockNumber, 10) + "_" + strconv.Itoa(offset)
}