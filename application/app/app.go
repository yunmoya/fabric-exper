package main

import (
	peerConfig "app/config"
	"app/contract"
	"app/myabi"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	CSPNUM                 = 3
	REQ_PORT               = 8080
	peerConsensusThreshold = 2
	channelName            = "lccch"
	ecContractName         = "ec"
	fairContractName       = "fair"
	assignPath             = "/assignInfo/assign"
)

var peerInfo = new(peerConfig.PeerInfo)
var IPArr = [CSPNUM + 1]string{"", "10.1.0.133", "10.1.0.154", "10.1.0.155"}

type VMReq struct {
	ID              string `json:"ID"`              // user request id
	UserId          string `json:"UserId"`          // user id
	PubKey          []byte `json:"PubKey"`          // user public key
	Config          int    `json:"Configuration"`   // cpu num
	Duration        int    `json:"Duration"`        // duration for which the VM is requested
	EncryptRequired bool   `json:"EncryptRequired"` //true：encryption required false: no encryption required
}

type ReqData struct {
	User            common.Address
	UserId          string // user id
	PubKey          []byte // user public key
	Config          int    // cpu num
	Duration        int    // duration for which the VM is requested
	EncryptRequired bool   //true：encryption required false: no encryption required
}

type ReqBody struct {
	Config   int    `json:"config"`
	Duration int    `json:"duration"`
	UserId   string `json:"userId"`
}

type RespBody struct {
	Msg      string   `json:"msg"`
	Code     int      `json:"code"`
	AssignVO AssignVO `json:"data"`
}

type AssignVO struct {
	VmId       uint64 `json:"vmId"`
	UserId     string `json:"userId"`
	VmName     string `json:"vmName"`
	AssignTime string `json:"assignTime"`
	EndTime    string `json:"endTime"`
}

func main() {
	log.Println("============ application starts ============")
	err := peerConfig.LoadPeerInfo("config.yaml", peerInfo)
	if err != nil {
		log.Panic(err)
	}

	// fabric client config
	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	gw := createFabricClient(clientConnection)
	defer clientConnection.Close()
	defer gw.Close()
	network := gw.GetNetwork(channelName)

	// fabric contract
	ecContract := network.GetContract(ecContractName)
	fairContract := network.GetContract(fairContractName)
	contract.InitECLedger(ecContract)
	contract.InitFairLedger(fairContract)

	// todo: geth client config
	// client, err := ethclient.Dial("wss://goerli.infura.io/ws/v3/547bcf201d264561b95c50860d2dddff")
	client, err := ethclient.Dial("ws://localhost:7545") //ganache
	if err != nil {
		log.Fatal(err)
	}

	// contractAddress := common.HexToAddress("0x74770669068090D6dCeA5163aBD5af61829A647a")
	contractAddress := common.HexToAddress("0x59Af076b2A8f82A17062c78626B226A1cAd5CACC") //ganache
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
	}

	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal(err)
	}

	contractAbi, err := abi.JSON(strings.NewReader(string(myabi.UserreqMetaData.ABI)))

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			log.Print("New Event:")
			vLogJson, err := json.Marshal(vLog)
			if err != nil {
				log.Fatal(err)
			}
			log.Println(string(vLogJson)) // pointer to event log
			// if get new block in public blockchain
			// request propagation contract(ec)
			// ec >= sum/2 => schedule contract(fair)
			// 1. Get request, blockNumber and offset in the newest block
			blockNumber := vLog.BlockNumber
			offset := vLog.TxIndex
			reqData := new(ReqData)
			err = contractAbi.UnpackIntoInterface(reqData, "NewRequest", vLog.Data)
			if err != nil {
				log.Fatal(err)
			}
			log.Print("Parse request data successfully: %v", reqData)
			req := VMReq{
				ID:     GetECAssetId(blockNumber, offset),
				UserId: reqData.UserId, Config: reqData.Config,
				Duration:        reqData.Duration,
				PubKey:          reqData.PubKey,
				EncryptRequired: reqData.EncryptRequired,
			}
			log.Print("The user request for private blockchain is: %v", req)
			// 2. Get the EC Asset Id
			assetECId := GetECAssetId(blockNumber, offset)
			// 3. Check if it is exist in private blockchain
			if contract.ECAssetExist(ecContract, assetECId) {
				// 4-1. ec+1
				contract.EndorsementIncAsync(ecContract, assetECId)
			} else {
				// 4-2. create new Asset
				contract.CreateECLedger(ecContract, blockNumber, int(offset))
			}

			// 5. Check if ecNum > 3/2
			ecAsset := contract.ReadECAssetByID(ecContract, assetECId)
			if ecAsset.EndorsementCount >= peerConsensusThreshold && ecAsset.Status == 0 {
				// 6. update status to completed(1)
				contract.ChangeECAssetStatusAsync(ecContract, assetECId, 1)
				// 7. fair scheduled contract process request
				ProcessReq(fairContract, req)
			}
		}
	}
}

func createFabricClient(clientConnection *grpc.ClientConn) *client.Gateway {
	id := newIdentity()
	sign := newSign()

	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		log.Panic(err)
	}
	return gw
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	var tlsCertPath = peerInfo.TlsCertPath
	var gatewayPeer = peerInfo.GatewayPeer
	var peerEndpoint = peerInfo.PeerEndpoint

	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		log.Panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		log.Panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	var certPath = peerInfo.CertPath
	var mspID = peerInfo.Mspid

	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	var keyPath = peerInfo.KeyPath

	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func GetECAssetId(blockNumber uint64, offset uint) string {
	return "asset" + strconv.FormatUint(blockNumber, 10) + "-" + string(offset)
}

func ProcessReq(fairContract *client.Contract, req VMReq) {
	cspId := contract.SelectCSP(fairContract, req.Config)
	if cspId == -1 {
		log.Printf("select csp fail, the request's detail is %v", req.UserId, req)
		return
	}

	assignVO, err := GetAssignInfo(cspId, req)
	if err != nil {
		log.Panic(err)
	}
	if assignVO == nil {
		log.Printf("process user:%s request fail, the request's detail is %v", req.UserId, req)
		return
	} else {
		log.Printf("process %s request success, the request's detail is %v, the assign information is %v", req.UserId, req, assignVO)
	}
	contract.UpdateProportionsAsync(fairContract)
	// todo: send to the signature-based consensus...
}

func GetAssignInfo(cspId int, vmReq VMReq) (*AssignVO, error) {
	ip := IPArr[cspId]
	url := "http://" + ip + ":" + strconv.Itoa(REQ_PORT) + assignPath
	reqBodyContent := ReqBody{Config: vmReq.Config, Duration: vmReq.Duration, UserId: vmReq.UserId}
	reqBodyContentJson, err := json.Marshal(reqBodyContent)
	if err != nil {
		return nil, fmt.Errorf("Marshal RequestParam fail, err:%v", err)
	}
	reqBody := strings.NewReader(string(reqBodyContentJson))
	resp, err := http.Post(url, "application/json", reqBody)
	if err != nil {
		return nil, fmt.Errorf("Http post fail, url: %s, reqBody: %s, err: %v", url, reqBody, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Response body read fail, err: %v", err)
	}
	respBody := new(RespBody)
	err = json.Unmarshal(body, &respBody)
	log.Printf("Get response msg:\ncode: %d\nmsg: %s", respBody.Code, respBody.Msg)
	if respBody.Code == 200 {
		return &respBody.AssignVO, nil
	} else {
		return nil, nil
	}

}
