package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/psanford/uhid"
	"golang.org/x/crypto/chacha20poly1305"
)

const BusUSB = 0x03

var (
	masterPrivateKey []byte
	signCounter      uint32
)

func main() {
	masterPrivateKey = mustRand(chacha20poly1305.KeySize)

	err := run()
	if err != nil {
		panic(err)
	}
}

// src: http://www.usb.org/developers/hidpage/HUTRR48.pdf
var rdesc = []byte{
	0x06, 0xd0, 0xf1, //	USAGE_PAGE (FIDO Alliance)
	0x09, 0x01, //				USAGE (U2F HID Authenticator Device)
	0xa1, 0x01, //				COLLECTION (Application)
	0x09, 0x20, //					USAGE (Input Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x81, 0x02, //					INPUT (Data,Var,Abs)
	0x09, 0x21, //					USAGE (Output Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x91, 0x02, //					OUTPUT (Data,Var,Abs)
	0xc0, //							END_COLLECTION
}

const (
	frameTypeInit = 0x80
	frameTypeCont = 0x00

	CmdPing  CmdType = 0x01 // Echo data through local processor only
	CmdMsg   CmdType = 0x03 // Send U2F message frame
	CmdLock  CmdType = 0x04 // Send lock channel command
	CmdInit  CmdType = 0x06 // Channel initialization
	CmdWink  CmdType = 0x08 // Send device identification wink
	CmdCbor  CmdType = 0x10 // Send encapsulated CTAP CBOR
	CmdSync  CmdType = 0x3c // Protocol resync command
	CmdError CmdType = 0x3f // Error response

	vendorSpecificFirstCmd = 0x40
	vendorSpecificLastCmd  = 0x7f

	reportLen            = 64
	initialPacketDataLen = reportLen - 7
	contPacketDataLen    = reportLen - 5

	u2fProtocolVersion = 2
	deviceMajor        = 1
	deviceMinor        = 0
	deviceBuild        = 0
	winkCapability     = 0x01
	cborCapability     = 0x04
)

type CmdType uint8

func (c CmdType) IsVendorSpecific() bool {
	return c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd
}

func (c CmdType) String() string {
	switch c {
	case CmdPing:
		return "CmdPing"
	case CmdMsg:
		return "CmdMsg"
	case CmdLock:
		return "CmdLock"
	case CmdInit:
		return "CmdInit"
	case CmdWink:
		return "CmdWink"
	case CmdSync:
		return "CmdSync"
	case CmdError:
		return "CmdError"
	case CmdCbor:
		return "CmdCbor"
	}

	if c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd {
		return fmt.Sprintf("CmdVendor<%d>", c)
	}
	return fmt.Sprintf("CmdUnknown<%d>", c)
}

func run() error {
	d, err := uhid.NewDevice("soft-fido", rdesc)
	if err != nil {
		return err
	}

	d.Data.Bus = BusUSB
	d.Data.VendorID = 0x15d9
	d.Data.ProductID = 0x0a37

	ctx := context.Background()
	evtChan, err := d.Open(ctx)
	if err != nil {
		return err
	}

	channels := make(map[uint32]bool)
	allocateChan := func() (uint32, bool) {
		for k := 1; k < (1<<32)-1; k++ {
			inUse := channels[uint32(k)]
			if !inUse {
				channels[uint32(k)] = true
				return uint32(k), true
			}
		}
		return 0, false
	}

	pktChan := make(chan Packet)

	go parsePackets(evtChan, pktChan)

	for {
		var (
			innerMsg  []byte
			needSize  uint16
			reqChanID uint32
			cmd       CmdType
		)

		for pkt := range pktChan {
			if pkt.IsInitial {
				if len(innerMsg) > 0 {
					log.Print("new initial packet while pending packets still exist")
					innerMsg = make([]byte, 0)
					needSize = 0
				}
				needSize = pkt.TotalSize
				reqChanID = pkt.ChannelID
				cmd = pkt.Command
			}
			innerMsg = append(innerMsg, pkt.Data...)
			if len(innerMsg) >= int(needSize) {
				break
			}
		}

		innerMsg = innerMsg[:int(needSize)]

		if cmd == CmdInit {
			chanID, ok := allocateChan()
			if !ok {
				log.Fatalf("Channel id exhaustion")
			}

			var nonce [8]byte
			copy(nonce[:], innerMsg)

			resp := newInitResponse(chanID, nonce)

			log.Printf("send resp: %+v\n", resp)

			err := writeRespose(d, reqChanID, CmdInit, resp.Marshal(), 0)
			if err != nil {
				log.Printf("Write Init resp err: %s", err)
				continue
			}
		} else if cmd == CmdMsg {
			req, err := decodeAuthenticatorRequest(innerMsg)
			if err != nil {
				log.Printf("decode authenticator req err: %s", err)
				continue
			}

			if req.Command == AuthenticatorAuthenticateCmd {
				log.Printf("got AuthenticatorAuthenticateCmd req")
				log.Printf("req: %+v", req.Authenticate)

				handleAuthenticate(ctx, d, reqChanID, cmd, req)
			} else if req.Command == AuthenticatorRegisterCmd {
				log.Printf("got AuthenticatorRegisterCmd req")
				handleRegister(ctx, d, reqChanID, cmd, req)
			}
		} else {
			log.Printf("send Cmd not supported err")
			writeRespose(d, reqChanID, cmd, nil, swInsNotSupported)
		}
	}
}

func handleAuthenticate(ctx context.Context, d *uhid.Device, reqChanID uint32, cmd CmdType, req *AuthenticatorRequest) {

	aead, err := chacha20poly1305.NewX(masterPrivateKey)
	if err != nil {
		panic(err)
	}

	if len(req.Authenticate.KeyHandle) < chacha20poly1305.NonceSizeX {
		log.Fatalf("incorrect size for key handle: %d smaller than nonce)", len(req.Authenticate.KeyHandle))
	}
	nonce := req.Authenticate.KeyHandle[:chacha20poly1305.NonceSizeX]
	cipherText := req.Authenticate.KeyHandle[chacha20poly1305.NonceSizeX:]

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, req.Authenticate.ApplicationParam[:]...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	childPrivateKey, err := aead.Open(nil, nonce, cipherText, sum)
	if err != nil {
		log.Printf("decrypt key handle failed")
		err := writeRespose(d, reqChanID, cmd, nil, swWrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	if req.Authenticate.Ctrl == ctrlCheckOnly {
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := writeRespose(d, reqChanID, cmd, nil, swConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == ctrlEnforeUserPresenceAndSign {
		childCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		defer cancel()
		ok, _ := ConfirmPresence(childCtx, "FIDO Confirm Authenticate")
		if !ok {
			err := writeRespose(d, reqChanID, cmd, nil, swConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		} else {
			userPresent = 0x01
		}
	}
	signCounter++

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	var ecdsaKey ecdsa.PrivateKey

	ecdsaKey.D = new(big.Int).SetBytes(childPrivateKey)
	ecdsaKey.PublicKey.Curve = elliptic.P256()
	ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(ecdsaKey.D.Bytes())

	sig, err := ecdsa.SignASN1(rand.Reader, &ecdsaKey, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = writeRespose(d, reqChanID, cmd, out.Bytes(), swNoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

func handleRegister(ctx context.Context, d *uhid.Device, reqChanID uint32, cmd CmdType, req *AuthenticatorRequest) {
	childCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	ok, _ := ConfirmPresence(childCtx, "FIDO Confirm Register")
	if ok {
		curve := elliptic.P256()

		childPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		metadata := []byte("fido_wrapping_key")
		metadata = append(metadata, req.Register.ApplicationParam[:]...)
		h := sha256.New()
		h.Write(metadata)
		sum := h.Sum(nil)

		aead, err := chacha20poly1305.NewX(masterPrivateKey)
		if err != nil {
			panic(err)
		}

		nonce := mustRand(chacha20poly1305.NonceSizeX)
		encryptedChildPrivateKey := aead.Seal(nil, nonce, childPrivateKey, sum)

		keyHandle := make([]byte, 0, len(nonce)+len(encryptedChildPrivateKey))
		keyHandle = append(keyHandle, nonce...)
		keyHandle = append(keyHandle, encryptedChildPrivateKey...)

		if len(keyHandle) > 255 {
			panic("keyHandle is too big")
		}

		childPubKey := elliptic.Marshal(curve, x, y)

		var toSign bytes.Buffer
		toSign.WriteByte(0)
		toSign.Write(req.Register.ApplicationParam[:])
		toSign.Write(req.Register.ChallengeParam[:])
		toSign.Write(keyHandle)
		toSign.Write(childPubKey)

		sigHash := sha256.New()
		sigHash.Write(toSign.Bytes())

		sigR, sigS, err := ecdsa.Sign(rand.Reader, attestationPrivateKey, sigHash.Sum(nil))
		if err != nil {
			log.Fatalf("attestation sign err: %s", err)
		}

		var out bytes.Buffer
		out.WriteByte(0x05) // reserved value
		out.Write(childPubKey)
		out.WriteByte(byte(len(keyHandle)))
		out.Write(keyHandle)
		out.Write(attestationCertDer)
		sig := elliptic.Marshal(elliptic.P256(), sigR, sigS)
		out.Write(sig)

		err = writeRespose(d, reqChanID, cmd, out.Bytes(), swNoError)
		if err != nil {
			log.Printf("write register response err: %s", err)
			return
		}
	} else {
		err := writeRespose(d, reqChanID, cmd, nil, swConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func writeRespose(d *uhid.Device, chanID uint32, cmd CmdType, data []byte, status uint16) error {

	initial := true
	pktSize := initialPacketDataLen

	if status > 0 {
		statusBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(statusBytes, status)
		data = append(data, statusBytes...)
	}

	totalSize := uint16(len(data))
	var seqNo uint8
	for len(data) > 0 {
		sliceSize := pktSize
		if len(data) < sliceSize {
			sliceSize = len(data)
		}

		pktData := data[:sliceSize]
		data = data[sliceSize:]

		if initial {
			initial = false
			pktSize = contPacketDataLen
			frame := frameInit{
				ChannelID:       chanID,
				Command:         uint8(cmd) | frameTypeInit,
				Data:            pktData,
				TotalPayloadLen: totalSize,
			}

			payload := frame.Marshal()

			resp := uhid.Input2Request{
				RequestType: uhid.Input2,
				DataSize:    uint16(len(payload)),
			}
			copy(resp.Data[:], payload)

			err := d.WriteEvent(resp)
			if err != nil {
				return err
			}
		} else {
			frame := frameCont{
				ChannelID: chanID,
				SeqNo:     seqNo,
				Data:      pktData,
			}

			payload := frame.Marshal()

			resp := uhid.Input2Request{
				RequestType: uhid.Input2,
				DataSize:    uint16(len(payload)),
			}
			copy(resp.Data[:], payload)

			err := d.WriteEvent(resp)
			if err != nil {
				return err
			}
			seqNo++
		}
	}

	return nil
}

type frameInit struct {
	ChannelID       uint32
	Command         uint8
	Data            []byte
	TotalPayloadLen uint16
}

func (fi *frameInit) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.Command)
	binary.Write(buf, binary.BigEndian, fi.TotalPayloadLen)
	buf.Write(fi.Data)
	if buf.Len() < initialPacketDataLen {
		pad := make([]byte, initialPacketDataLen-buf.Len())
		buf.Write(pad)
	}

	return buf.Bytes()
}

type frameCont struct {
	ChannelID uint32
	SeqNo     uint8
	Data      []byte
}

func (fi *frameCont) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.SeqNo)
	buf.Write(fi.Data)
	if buf.Len() < contPacketDataLen {
		pad := make([]byte, contPacketDataLen-buf.Len())
		buf.Write(pad)
	}
	return buf.Bytes()
}

type initResponse struct {
	Nonce              [8]byte
	Channel            uint32
	ProtocolVersion    byte
	MajorDeviceVersion byte
	MinorDeviceVersion byte
	BuildDeviceVersion byte
	RawCapabilities    byte
}

func newInitResponse(channelID uint32, nonce [8]byte) *initResponse {
	return &initResponse{
		Nonce:              nonce,
		Channel:            channelID,
		ProtocolVersion:    u2fProtocolVersion,
		MajorDeviceVersion: deviceMajor,
		MinorDeviceVersion: deviceMinor,
		BuildDeviceVersion: deviceBuild,
		// RawCapabilities:    winkCapability | cborCapability,
	}
}

func (resp *initResponse) Marshal() []byte {
	buf := new(bytes.Buffer)
	buf.Write(resp.Nonce[:])
	binary.Write(buf, binary.BigEndian, resp.Channel)
	buf.Write([]byte{
		resp.ProtocolVersion,
		resp.MajorDeviceVersion,
		resp.MinorDeviceVersion,
		resp.BuildDeviceVersion,
		resp.RawCapabilities,
	})

	return buf.Bytes()
}

func parsePackets(evtChan chan uhid.Event, pktChan chan Packet) {
	for evt := range evtChan {
		if evt.Err != nil {
			log.Fatalf("got evt err: %s", evt.Err)
		}
		log.Printf("got evt: %s", evt.Type)
		// log.Printf("data: (%d) %+v", len(evt.Data), evt.Data)

		// Output means the kernel has sent us data
		if evt.Type == uhid.Output {

			r := newPacketReader(bytes.NewReader(evt.Data))
			b1 := make([]byte, 1)
			r.ReadFull(b1) // ignore first byte

			var channelID uint32
			r.Read(binary.BigEndian, &channelID)

			_, err := r.ReadFull(b1)
			if err != nil {
				log.Printf("U2F protocol read error")
				continue
			}
			typeOrSeqNo := b1[0]
			if typeOrSeqNo&frameTypeInit == frameTypeInit {
				typ := typeOrSeqNo
				cmd := typ ^ frameTypeInit

				var totalSize uint16
				r.Read(binary.BigEndian, &totalSize)

				data := make([]byte, initialPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					IsInitial: true,
					Command:   CmdType(cmd),
					TotalSize: totalSize,
					Data:      data,
				}

				log.Printf("Got: %s %+v\n", p.Command, p)
				pktChan <- p
			} else {
				seqNo := typeOrSeqNo

				data := make([]byte, contPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					SeqNo:     seqNo,
					Data:      data,
				}

				log.Printf("Got: %+v\n", p)
				pktChan <- p
			}
		}
	}
}

type Packet struct {
	ChannelID uint32
	IsInitial bool
	Command   CmdType
	SeqNo     byte
	TotalSize uint16
	Data      []byte
}

func newPacketReader(r io.Reader) *packetReader {
	return &packetReader{
		r: r,
	}
}

type packetReader struct {
	r   io.Reader
	err error
}

func (r *packetReader) Error() error {
	return r.err
}

func (pr *packetReader) Read(order binary.ByteOrder, data interface{}) error {
	if pr.err != nil {
		return pr.err
	}

	err := binary.Read(pr.r, order, data)
	if err != nil {
		pr.err = err
	}
	return err
}

func (pr *packetReader) ReadFull(b []byte) (int, error) {
	if pr.err != nil {
		return 0, pr.err
	}

	n, err := io.ReadFull(pr.r, b)
	if err != nil {
		pr.err = err
		return n, err
	}
	return n, nil
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
