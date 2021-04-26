package main

import (
	"fmt"
	"log"
)

const (
	AuthenticatorRegisterCmd     = 0x01
	AuthenticatorAuthenticateCmd = 0x02
	AuthenticatorVersionCmd      = 0x03

	swNoError                = 0x9000 // The command completed successfully without error.
	swConditionsNotSatisfied = 0x6985 // The request was rejected due to test-of-user-presence being required.
	sWrongData               = 0x6A80 // The request was rejected due to an invalid key handle.
	swWrongLength            = 0x6700 // The length of the request was invalid
	swClaNotSupported        = 0x6E00 // The Class byte of the request is not supported
	swInsNotSupported        = 0x6D00 // The Instruction of the request is not supported
)

type AuthenticatorRequest struct {
	Command uint8
	Param1  uint8
	Param2  uint8
	Size    int
	Data    []byte

	Register *AuthenticatorRegisterReq
}

type AuthenticatorRegisterReq struct {
	ChallengeParam   [32]byte
	ApplicationParam [32]byte
}

type AuthenticatorResponse struct {
	Data   []byte
	Status uint16
}

func decodeAuthenticatorRequest(raw []byte) (*AuthenticatorRequest, error) {
	if len(raw) < 7 {
		return nil, fmt.Errorf("authenticator request too short")
	}

	req := AuthenticatorRequest{
		Command: raw[1],
		Param1:  raw[2],
		Param2:  raw[3],
		Size:    (int(raw[4]) << 16) | (int(raw[5]) << 8) | int(raw[6]),
		Data:    raw[7:],
	}

	log.Printf("got authenticatorrequest data: %+v", req.Data)

	if req.Command == AuthenticatorRegisterCmd {
		var reg AuthenticatorRegisterReq
		if len(req.Data) != len(reg.ChallengeParam)+len(reg.ApplicationParam) {
			return nil, fmt.Errorf("register request incorrect size: %d", len(req.Data))
		}

		copy(reg.ChallengeParam[:], req.Data[:32])
		copy(reg.ApplicationParam[:], req.Data[32:])
		req.Register = &reg
	}

	return &req, nil
}
