package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"github.com/schmichael/gophernet"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"
)

func main() {
	id1 := "99375318-11c4-4a77-ba42-f7c08ca7b9d0"
	id2 := "ff375318-11c4-4a77-ba42-f7c08ca7b9d0"
	privkeyHex, err := ioutil.ReadFile(".gn_ecdsa")
	if err != nil {
		panic(err)
	}
	privkey, err := hex.DecodeString(string(privkeyHex[:len(privkeyHex)-1]))
	if err != nil {
		panic(err)
	}

	key := new(ecdsa.PrivateKey)
	key.D = big.NewInt(0)
	key.D.SetBytes(privkey)
	key.PublicKey.Curve = elliptic.P256()
	xb, _ := hex.DecodeString("212d26c6744803803e2f81fa117630a72eaf8a7c12f16e4e1b0188785a57c783256")
	x := big.NewInt(0)
	x.SetBytes(xb)
	key.PublicKey.X = x

	yb, _ := hex.DecodeString("b0802aac16e521569f549092c41c1b295e9ff627534d1b28fe050a37f5280ac9255")
	y := big.NewInt(0)
	y.SetBytes(yb)
	key.PublicKey.Y = y

	ids := map[string]*ecdsa.PublicKey{
		id1: &key.PublicKey,
		id2: &key.PublicKey,
	}
	node1 := gophernet.NewNode(id1, key, 100, ids)
	node2 := gophernet.NewNode(id2, key, 100, ids)

	errChan := make(chan error)
	stopChan := make(chan struct{})
	msgChan1 := make(chan *gophernet.Message, 1)
	msgChan2 := make(chan *gophernet.Message, 1)
	go gophernet.Listen(node1, ":7890", errChan, stopChan, msgChan1)
	go gophernet.Listen(node2, ":7891", errChan, stopChan, msgChan2)

	{
		log.Printf("MAIN: Giving listeners a couple seconds to start.")
		var err error
		select {
		case err = <-errChan:
			log.Printf("MAIN: Error: %v", err)
		case <-time.After(2 * time.Second):
		}

		if err != nil {
			log.Printf("MAIN: At least one error, stopping")
			close(stopChan)
			for err := range errChan {
				log.Print("MAIN: Error: %v", err)
			}
		}
	}

	c, err := net.Dial("tcp", "0.0.0.0:7891")
	if err != nil {
		panic(err)
	}
	p := node2.AddPeer(c)
	go gophernet.Handle(node2.ID, p, node2.DropPeer, node2.GetKey, stopChan, msgChan2)

	node2.Broadcast(&gophernet.Message{})

	select {
	case err = <-errChan:
		log.Printf("MAIN: Error: %v", err)
	case msg := <-msgChan1:
		log.Printf("MAIN: msgChan1: %#v", msg)
	case msg := <-msgChan2:
		log.Printf("MAIN: msgChan2: %#v", msg)
	}
}
