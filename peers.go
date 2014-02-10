package gophernet

import (
	"crypto/ecdsa"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/schmichael/gophernet/uuid"
)

var (
	OutgoingMessageBuffer = 3
)

type Peer struct {
	Conn      net.Conn
	LastRecv  time.Time
	writeChan chan *Message
	closed    bool
	closeLock sync.Mutex
}

func newPeer(c net.Conn) *Peer {
	p := &Peer{
		Conn:      c,
		LastRecv:  time.Now(),
		writeChan: make(chan *Message, 3),
	}
	go p.writer()
	return p
}

func (p *Peer) Key() string {
	return p.Conn.RemoteAddr().String()
}

func (p *Peer) Close() error {
	p.closeLock.Lock()
	defer p.closeLock.Unlock()
	if p.closed {
		return syscall.EINVAL
	}
	close(p.writeChan)
	return p.Conn.Close()
}

func (p *Peer) writer() {
	defer p.Close()
	for {
		msg, ok := <-p.writeChan
		if !ok {
			log.Printf("Writer stopped for peer %s", p.Key())
			return
		}
		if err := binary.Write(p.Conn, binary.BigEndian, &msg.RawHeader); err != nil {
			log.Printf("Error writing header to %s: %v", p.Key(), err)
			return
		}
		for off := 0; off < len(msg.RawBody); {
			n, err := p.Conn.Write(msg.RawBody[off:])
			if err != nil {
				log.Printf("Error writing body to %s: %v", p.Key(), err)
				return
			}
			off += n
		}
	}
}

type Node struct {
	// Max peers
	max      int
	peers    map[string]*Peer
	peerLock sync.Mutex
	wg       sync.WaitGroup

	ID  uuid.UUID
	key *ecdsa.PrivateKey

	// UUID:Public Key
	identities map[string]*ecdsa.PublicKey
	idLock     sync.Mutex
}

func NewNode(id string, key *ecdsa.PrivateKey, maxConns int, identities map[string]*ecdsa.PublicKey) *Node {
	if maxConns < 1 {
		panic("Node must have a maximum number of peers > 0")
	}
	return &Node{
		ID:         uuid.Parse(id),
		key:        key,
		max:        maxConns,
		peers:      make(map[string]*Peer),
		identities: identities,
	}
}

// AddPeer adds a connected peer to the node's peer list. If the list is full,
// the oldest peer will be closed and dropped.
func (n *Node) AddPeer(c net.Conn) *Peer {
	p := newPeer(c)

	n.peerLock.Lock()
	defer n.peerLock.Unlock()

	// Make sure this isn't a reconnect
	if v, ok := n.peers[p.Key()]; ok {
		// We have an old connection for this peer. Replace it.
		v.Conn.Close()
		n.peers[p.Key()] = p
	} else if len(n.peers) == n.max {
		// Make room for the new peer by removing the oldest idle one
		var oldest *Peer
		for _, v := range n.peers {
			if oldest == nil || v.LastRecv.Before(oldest.LastRecv) {
				oldest = v
			}
		}
		oldest.Conn.Close()
		delete(n.peers, oldest.Key())
	} else {
		// Adding a new peer, increment waitgroup
		n.wg.Add(1)
	}
	n.peers[p.Key()] = p
	return p
}

func (n *Node) GetKey(id string) *ecdsa.PublicKey {
	n.idLock.Lock()
	defer n.idLock.Unlock()
	if v, ok := n.identities[id]; ok {
		return v
	} else {
		return nil
	}
}

// DropPeer removes a peer from the node's peer list.
func (n *Node) DropPeer(p *Peer) {
	n.peerLock.Lock()
	defer n.peerLock.Unlock()
	delete(n.peers, p.Key())
	n.wg.Done()
}

func (n *Node) Broadcast(msg *Message) {
	n.peerLock.Lock()
	defer n.peerLock.Unlock()

	for _, peer := range n.peers {
		peer.writeChan <- msg
	}
}

// Asynchronously closes waitChan when no peers are left.
func (n *Node) Wait(waitChan chan struct{}) {
	go func() {
		n.wg.Wait()
		close(waitChan)
	}()
}
