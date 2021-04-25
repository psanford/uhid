// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package uhid supports creating, handling and destroying devices created
// via /dev/uhid.
package uhid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	// hidMaxDescriptorSize represents the maximum length of a
	// descriptor or an event injected. It matches UHID_DATA_MAX
	// from uhid.h.
	hidMaxDescriptorSize = 4096

	// uhidEventSize refers to the size of struct uhid_event from
	// uhid.h. This is the struct that is always written by the
	// kernel to /dev/uhid.
	uhidEventSize = 4380
)

// EventType is the type used to encapsulate the different request
// types that can be written by the kernel or user to /dev/uhid.
type EventType uint32

const (
	// The following constants are from enum uhid_event_type in uhid.h.
	// These constants are used for event handlers. If the user wishes
	// to handle an event UHIDEvent for a device d  using the handler
	// function handlerFunction then the corresponding handler must be
	// set in the EventHandlers map like so:
	// d.EventHandlers[uhid.UHIDEvent] = handlerFunction

	// Destroy destroys the device freeing up it's resources.
	Destroy EventType = 1
	// Start is written by the kernel to acknowledge the creation of
	// a device.
	Start = 2
	// Stop is written by the kernel to acknowledge the destruction
	// of a device.
	Stop = 3
	// Open is written by the kernel to signal that the data being
	// provided by the device is being read.
	Open = 4
	// Close is written by the kernel to signal that no more processes
	// are reading this device's data.
	Close = 5
	// Output is written by the kernel to signal that the HID device
	// driver wants to send raw data to the I/O device on the interrupt
	// channel.
	Output = 6
	// GetReport is written by the kernel to signal that the kernel
	// driver wants to perform a GET_REPORT request on the control
	// channeld as described in the HID specs.
	GetReport = 9
	// GetReportReply must be written by the user as a reply to a
	// UHIDGetReport request.
	GetReportReply = 10
	// Create2 is written by the user to create a device.
	Create2 = 11
	// Input2 is used to inject events to the device.
	Input2 = 12
	// SetReport is written by the kernel to signal that the kernel
	// driver wants to perform a SET_REPORT request on the control
	// channeld as described in the HID specs.
	SetReport = 13
	// SetReportReply must be written by the user as a reply to a
	// SetReport request.
	SetReportReply = 14
)

// ReadStatus is returned by Dispatch to signal the multiple
// results of reading from /dev/uhid
type ReadStatus uint8

const (
	// StatusOK signals that an event was read and no problem was
	// encountered.
	StatusOK ReadStatus = iota
	// StatusNoEvent signals that no event was read.
	StatusNoEvent
)

// RNumType is the type used for the rnum field in get report
// requests.
type RNumType uint8

// GetReportRequest replicates struct uhid_get_report_req in uhid.h.
// It is used to read GetReport requests written by the kernel and
// handling them afterwards if necessary.
type GetReportRequest struct {
	RequestType uint32
	ID          uint32
	RNum        RNumType
	RType       uint8
}

// GetReportReplyRequest replicates struct uhid_get_report_reply_req
// in uhid.h. It should be written to Device.File in response to a
// GetReportRequest by the kernel.
type GetReportReplyRequest struct {
	RequestType uint32
	ID          uint32
	Err         uint16
	DataSize    uint16
	Data        [hidMaxDescriptorSize]byte
}

// uhidCreate2Request replicates struct uhid_create2_req in uhid.h.
// Create requests are written into /dev/uhid in order to create a
// virtual HID device. This device will have the given name and IDs as
// well as respond to the given HID descriptor.
type uhidCreate2Request struct {
	requestType    uint32
	name           [128]byte
	phys           [64]byte
	uniq           [64]byte
	descriptorSize uint16
	bus            uint16
	vendorID       uint32
	productID      uint32
	version        uint32
	country        uint32
	descriptor     [hidMaxDescriptorSize]byte
}

// DeviceData encapsulates the non-trivial data that will then be
// copied over to a create request or be used to get information from
// the device. The fixed size byte arrays are meant to replicate those
// in struct uhid_create2_req in uhid.h.
type DeviceData struct {
	name       [128]byte
	phys       [64]byte
	uniq       [64]byte
	descriptor []byte
	Bus        uint16
	VendorID   uint32
	ProductID  uint32
}

// Device is the main interface carrying all of the created (or soon
// to be created) kernel device's information.
type Device struct {
	Data        DeviceData
	hidrawNodes []string
	eventNodes  []string
	file        *os.File

	eventChan chan Event
}

// Input2Request replicates struct uhid_input2_req in uhid.h.
// An input request is used to inject events into the created device.
type Input2Request struct {
	RequestType uint32
	DataSize    uint16
	Data        [hidMaxDescriptorSize]uint8
}

// NewDevice returns a device with the given name and descriptor.
func NewDevice(name string, descriptor []byte) (*Device, error) {
	if len(name) > 128 {
		return nil, fmt.Errorf("device name too long: got %d want %d or shorter", len(name), 128)
	}
	if len(descriptor) > hidMaxDescriptorSize {
		return nil, fmt.Errorf("device descriptor too long: got %d want %d or shorter", len(descriptor), hidMaxDescriptorSize)
	}
	d := Device{
		eventChan: make(chan Event),
	}
	copy(d.Data.name[:], name)
	d.Data.descriptor = append(d.Data.descriptor, descriptor...)
	return &d, nil
}

// Open creates a device with the attributes specified in
// d. Only after calling this function will the device be ready for
// the other operations.
func (d *Device) Open(ctx context.Context) (chan Event, error) {
	if d.Data.name == [128]byte{} || len(d.Data.descriptor) == 0 {
		return nil, errors.New("device has not been initialized")
	}

	var err error
	if d.file, err = os.OpenFile("/dev/uhid", os.O_RDWR, 0644); err != nil {
		return nil, fmt.Errorf("failed opening /dev/uhid file: %w", err)
	}

	// Check if uniq is empty.
	if d.Data.uniq == [64]byte{} {
		rand.Read(d.Data.uniq[:])
	}

	if err = d.WriteEvent(d.Data.createRequest()); err != nil {
		return nil, fmt.Errorf("failed writing uhid create request: %w", err)
	}

	go d.dispatch(ctx)
	evt := <-d.eventChan
	if evt.Err != nil {
		return nil, fmt.Errorf("kernel failed at creating the device: %w", evt.Err)
	}
	return d.eventChan, nil
}

// Close destroys the device specified in d by writing a destroy
// request to /dev/uhid. The file as well as the hidraw and event nodes
// are cleared.
func (d *Device) Close() error {
	if d.file != nil {
		if err := d.WriteEvent(Destroy); err != nil {
			return fmt.Errorf("failed writing uhid destroy request: %w", err)
		}
		if err := d.file.Close(); err != nil {
			return fmt.Errorf("failed closing file during device destruction: %w", err)
		}
	}
	return nil
}

// InjectEvent Injects an event into an existing device. The data array
// will vary from device to device.
func (d *Device) InjectEvent(data []uint8) error {
	if d.file == nil {
		return errors.New("device has not been initialized")
	}
	req := Input2Request{}
	req.RequestType = Input2
	req.DataSize = uint16(len(data))
	copy(req.Data[:len(data)], data)
	if err := d.WriteEvent(req); err != nil {
		return fmt.Errorf("failed writing input2 request: %w", err)
	}
	return nil
}

// HidrawNodes returns the /dev/hidraw* paths associated to this
// device.
func (d *Device) HidrawNodes(ctx context.Context) ([]string, error) {
	if d.file == nil {
		return nil, errors.New("device has not been initialized")
	}
	if d.hidrawNodes == nil {
		if err := deviceNodes(ctx, d); err != nil {
			return nil, err
		}
	}
	return d.hidrawNodes, nil
}

// EventNodes returns the /dev/input/event* paths associated to this
// device.
func (d *Device) EventNodes(ctx context.Context) ([]string, error) {
	if d.file == nil {
		return nil, errors.New("device has not been initialized")
	}
	if d.eventNodes == nil {
		if err := deviceNodes(ctx, d); err != nil {
			return nil, err
		}
	}
	return d.eventNodes, nil
}

// readEvent returns a buffer with information read from the given
// device's file. All events arriving to /dev/uhid will be of the
// form of struct uhid_event from uhid.h, which has a size of
// uhidEventSize.
func (d *Device) readEvent() ([]byte, error) {
	if d.file == nil {
		return nil, errors.New("device has not been initialized")
	}

	buf := make([]byte, uhidEventSize)
	n, err := d.file.Read(buf)
	if err != nil {
		return buf, err
	}
	if n != uhidEventSize {
		return buf, fmt.Errorf("unexpected number of bytes of UHID event; got %d, want %d", n, uhidEventSize)
	}
	return buf, nil
}

// WriteEvent will write the struct given in i into /dev/uhid and
// return an error if unsuccessful.
func (d *Device) WriteEvent(i interface{}) error {
	if d.file == nil {
		return errors.New("device has not been initialized")
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, i)
	if err != nil {
		return err
	}
	_, err = d.file.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// dispatch must be called when an event needs to be handled. Be sure
// to implement some method of checking if the event you wish to
// handle was indeed the one handled.
func (d *Device) dispatch(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	rawDataChan := make(chan []byte)
	errChan := make(chan error, 1)

	go func() {
		for {
			buf, err := d.readEvent()
			if err != nil {
				errChan <- err
				return
			}
			select {
			case rawDataChan <- buf:
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case buf := <-rawDataChan:
		reader := bytes.NewReader(buf[:4]) // We just want to read the first uint32 for now
		var eventType uint32
		if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {

			d.eventChan <- Event{
				Err: fmt.Errorf("failed parsing uhid file data into request: %w", err),
			}
			return
		}

		d.eventChan <- Event{
			Type: EventType(eventType),
			Data: buf,
		}
	case <-ctx.Done():
		d.eventChan <- Event{
			Err: ctx.Err(),
		}
		return
	}
}

type Event struct {
	Type EventType
	Err  error
	Data []byte
}

// Name returns the name of the device.
func (d *Device) Name() string {
	return string(d.Data.name[:])
}

// Phys returns the phys of the device.
func (d *Device) Phys() string {
	return string(d.Data.phys[:])
}

// Uniq returns the uniq of this device.
func (d *Device) Uniq() string {
	return string(d.Data.uniq[:])
}

// SetUniq sets the uniq of this device.
func (d *Device) SetUniq(uniq string) error {
	if len(uniq) > 64 {
		return fmt.Errorf("device name too long: got %d want %d or shorter", len(uniq), 64)
	}
	copy(d.Data.uniq[:], uniq)
	return nil
}

// Bus returns the bus of this device.
func (d *Device) Bus() uint16 {
	return d.Data.Bus
}

// VendorID returns the vendor id of this device.
func (d *Device) VendorID() uint32 {
	return d.Data.VendorID
}

// ProductID returns the product id of this device.
func (d *Device) ProductID() uint32 {
	return d.Data.ProductID
}

// createRequest returns a new uhidCreate2Request based on the data
// contained in deviceData.
func (dd *DeviceData) createRequest() uhidCreate2Request {
	req := uhidCreate2Request{
		requestType:    Create2,
		name:           dd.name,
		phys:           dd.phys,
		uniq:           dd.uniq,
		descriptorSize: uint16(len(dd.descriptor)),
		bus:            dd.Bus,
		vendorID:       dd.VendorID,
		productID:      dd.ProductID,
		version:        0,
		country:        0,
	}

	copy(req.descriptor[:], dd.descriptor)

	return req
}

// deviceNodes assigns to device d's hidRawNodes and eventNodes fields
// their corresponding nodes. These nodes refer to the
// /dev/input/event and /dev/hidraw nodes. These are obtained from
// /sys/bus/hid/devices which contains HID Device information.
func deviceNodes(ctx context.Context, d *Device) error {
	devicePath, err := devicePath(d.infoString())
	if err != nil {
		return err
	}
	if d.hidrawNodes, err = hidrawNodes(ctx, devicePath); err != nil {
		return err
	}
	d.eventNodes, err = eventNodes(devicePath)
	return err
}

// infoString returns a string of the form
// <d.Data.Bus>:<d.Data.VendorID>:<d.Data.ProductID>. Information
// regarding this device will be found under
// /sys/bus/hid/devices/<infoString>.<ID> where ID is a unique ID for
// each device the kernel recognizes.
func (d *Device) infoString() string {
	return fmt.Sprintf("%04X:%04X:%04X", d.Data.Bus, d.Data.VendorID, d.Data.ProductID)
}
