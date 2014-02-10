package gophernet

import (
	"crypto/ecdsa"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	"github.com/schmichael/gophernet/uuid"
)

var (
	// Time we give clients to send their payload before disconnecting
	ClientReadTimeout = 5 * time.Second
)

// Listen's forever on addr until stopChan closed.
//
// Sends an error or nil on errChan and closes it on exit. More than one error
// may be sent so receivers should range until chan is closed.
func Listen(peers *Node, addr string, errChan chan error, stopChan chan struct{}, msgChan chan<- *Message) {
	ln, err := listen(addr)
	if err != nil {
		errChan <- err
		close(errChan)
		return
	}

	defer func() {
		errChan <- ln.Close()
		close(errChan)
	}()

	for {
		select {
		case <-stopChan:
			// Recieved signal to close. Get out of here.
			return
		default:
		}

		// Set deadline before Accept() so we periodically check stopChan
		if err := ln.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
			errChan <- err
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				// Accept deadline hit, loop
				continue
			}
			errChan <- err
			return
		}

		go Handle(peers.ID, peers.AddPeer(conn), peers.DropPeer, peers.GetKey, stopChan, msgChan)
	}
}

func listen(addr string) (*net.TCPListener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func Handle(id uuid.UUID, p *Peer, drop func(*Peer), getKey func(string) *ecdsa.PublicKey, stopChan chan struct{}, msgChan chan<- *Message) {
	defer func() {
		p.Close()
		drop(p)
	}()

	for {
		select {
		case <-stopChan:
			// Recieved signal to close. Get out of here.
			return
		default:
		}

		// Set deadline before Read() so we periodically check stopChan
		if err := p.Conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("Error when setting header read deadline on %s: %v", p.Key(), err)
			return
		}
		hdr := &Header{}
		err := binary.Read(p.Conn, binary.BigEndian, hdr)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				// Read deadline hit, loop
				continue
			}
			return
		}
		p.LastRecv = time.Now()

		if hdr.Ping() {
			// Just a ping. We already set LastRecv, so continue on.
			continue
		}

		if errs := hdr.Valid(); len(errs) > 0 {
			for _, err := range errs {
				log.Printf("Invalid header from %s: %v", p.Key(), err)
			}
			return
		}

		msg := PartialMessage(hdr)
		// Deadline before Read()ing the body is used to disconnect slow clients
		if err := p.Conn.SetReadDeadline(time.Now().Add(ClientReadTimeout)); err != nil {
			log.Printf("Error when setting body read deadline on %s: %v", p.Key(), err)
			return
		}
		if n, err := io.ReadFull(p.Conn, msg.RawBody); err != nil {
			log.Printf("Error when reading body from %s after %d bytes: %v", p.Key(), n, err)
			return
		}

		// Verify the payload in the main read loop as if someone lies to us we
		// don't want to bother reading any more data from them.
		inID := uuid.UUID(hdr.Sender).String()
		if key := getKey(inID); key != nil {
			if !msg.Verify(key) {
				log.Printf("Message from %s via %s failed signature verification.", inID, p.Key())
				return
			}
		} else {
			// Messages with unknown IDs should just be dropped.
			log.Printf("Dropping message from %s via %s. Unknown ID.", inID, p.Key())
			continue
		}

		if id == uuid.UUID(hdr.Sender) {
			// Message to self, drop it
			continue
		}

		// Hand-off message for someone else to deal with a keep listening
		msgChan <- msg
	}
}
