package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	PrivateKeyToDecode = flag.String("pk", "", "Private key for decode")
)

func init() {
	receiveArguments()
}

func receiveArguments() {
	flag.Parse()
}

func main() {

	if *PrivateKeyToDecode == "" {
		createWallet()
	} else {
		decodeWallet(*PrivateKeyToDecode)
	}

}

func decodeWallet(privateKeyToDecode string) {
	privateKeyBytes, err := hexutil.Decode(privateKeyToDecode)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	printAddress(privateKey)
}

func createWallet() {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	fmt.Println("PRIVATE KEY")
	fmt.Println(hexutil.Encode(privateKeyBytes)) // 0xfad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19

	printAddress(privateKey)
}

func printAddress(privateKey *ecdsa.PrivateKey) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)

	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	fmt.Println("PUBLIC KEY")
	fmt.Println(hexutil.Encode(publicKeyBytes)) // 0x049a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	fmt.Println("ADDRESS")
	fmt.Println(address) // 0x96216849c49358B10257cb55b28eA603c874b05E

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])

	fmt.Println("HASH")
	fmt.Println(hexutil.Encode(hash.Sum(nil)[12:])) // 0x96216849c49358b10257cb55b28ea603c874b05e
}
