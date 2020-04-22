// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package uhid supports creating, handling and destroying devices created
// via /dev/uhid.
package uhid

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"chromiumos/tast/errors"
)

const (
	// hidMaxDescriptorSize defined here:
	// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/master:src/third_party/kernel/v4.4/include/uapi/linux/uhid.h;l=67?q=uhid.h&ss=chromiumos
	// hidMaxDescriptorSize represents the maximum length of a
	// descriptor or an event injected.
	hidMaxDescriptorSize = 4096

	// uhidEventSize refers to the size of this C struct:
	// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/master:src/third_party/kernel/v4.4/include/uapi/linux/uhid.h;l=179?q=uhid.h&ss=chromiumos
	// This is the struct that is always written by the kernel to
	// /dev/uhid.
	uhidEventSize = 4380
)

// EventType is the type used to encapsulate the different request
// types that can be written by the kernel or user to /dev/uhid.
type EventType uint32

const (
	// the following constants defined here:
	// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/master:src/third_party/kernel/v4.4/include/uapi/linux/uhid.h;l=26?q=uhid.h&ss=chromiumos
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

// GetReportRequest replicates the C struct found here:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/master:src/third_party/kernel/v4.4/include/uapi/linux/uhid.h;l=86
// It is used to read GetReport requests written by the kernel and
// handling them afterwards if necessary.
type GetReportRequest struct {
	RequestType uint32
	ID          uint32
	RNum        RNumType
	RType       uint8
}

// GetReportReplyRequest replicates the C struct found here:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/master:src/third_party/kernel/v4.4/include/uapi/linux/uhid.h;l=92
// It should be written to Device.File in response to a
// GetReportRequest by the kernel.
type GetReportReplyRequest struct {
	RequestType uint32
	ID          uint32
	Err         uint16
	DataSize    uint16
	Data        [hidMaxDescriptorSize]byte
}

// uhidCreate2Request replicates the C struct found here:
// https://cs.corp.google.com/chromeos_public/src/third_party/kernel/v4.14/include/uapi/linux/uhid.h?pv=1&l=45
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
// the device. The fixed size byte arrays are meant to replicate this
// struct:
// https://cs.corp.google.com/chromeos_public/src/third_party/kernel/v4.14/include/uapi/linux/uhid.h?pv=1&l=45
type DeviceData struct {
	name       [128]byte
	phys       [64]byte
	uniq       [64]byte
	descriptor [hidMaxDescriptorSize]byte
	bus        uint16
	vendorID   uint32
	productID  uint32
}

type eventHandler func(ctx context.Context, d *Device, buf []byte) error

// Device is the main interface carrying all of the created (or soon
// to be created) kernel device's information.
type Device struct {
	Data        DeviceData
	hidrawNodes []string
	eventNodes  []string
	file        *os.File

	// EventHandlers is used on a call to Dispatch to call the
	// corresponding handling function. If the user wishes to handle a
	// particular event then they must assign their handler function to
	// EventHandlers[UHIDEvent] where UHIDEvent is one of the UHID
	// constants defined above.
	EventHandlers map[uint32]eventHandler
}

// Input2Request replicates the C struct found here:
// https://cs.corp.google.com/chromeos_public/src/third_party/kernel/v4.14/include/uapi/linux/uhid.h?pv=1&l=45
// an input request is used to inject events into the created device.
type Input2Request struct {
	RequestType uint32
	DataSize    uint16
	Data        [hidMaxDescriptorSize]uint8
}

// NewDevice returns a device with the given name and descriptor.
func NewDevice(name, descriptor string) (*Device, error) {
	if len(name) > 128 {
		return nil, errors.Errorf("device name too long: got %d want %d or shorter", len(name), 128)
	}
	if len(descriptor) > hidMaxDescriptorSize {
		return nil, errors.Errorf("device descriptor too long: got %d want %d or shorter", len(descriptor), hidMaxDescriptorSize)
	}
	d := Device{}
	copy(d.Data.name[:], name)
	copy(d.Data.descriptor[:], descriptor)
	return &d, nil
}

// NewKernelDevice creates a device with the attributes specified in
// d. Only after calling this function will the device be ready for
// the other operations.
func (d *Device) NewKernelDevice(ctx context.Context) error {
	if d.Data.name == [128]byte{} || d.Data.descriptor == [hidMaxDescriptorSize]byte{} {
		return errors.New("device has not been initialized")
	}

	var err error
	if d.file, err = os.OpenFile("/dev/uhid", os.O_RDWR, 0644); err != nil {
		return errors.Wrap(err, "failed opening /dev/uhid file")
	}

	// Check if uniq is empty.
	if d.Data.uniq == [64]byte{} {
		uniq, _ := uuid.NewRandom()
		copy(d.Data.uniq[:], uniq[:])
	}

	if err = d.WriteEvent(d.Data.createRequest()); err != nil {
		return errors.Wrap(err, "failed writing uhid create request")
	}
	d.setDefaultHandlers()
	var status ReadStatus
	status, err = d.Dispatch(ctx)
	if status != StatusOK || err != nil {
		return errors.Wrap(err, "kernel failed at creating the device")
	}
	return nil
}

// Close destroys the device specified in d by writing a destroy
// request to /dev/uhid. The file as well as the hidraw and event nodes
// are cleared.
func (d *Device) Close() error {
	if d.file != nil {
		if err := d.WriteEvent(Destroy); err != nil {
			return errors.Wrap(err, "failed writing uhid destroy request")
		}
		if err := d.file.Close(); err != nil {
			return errors.Wrap(err, "failed closing file during device destruction")
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
		return errors.Wrap(err, "failed writing input2 request")
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
// form of this struct:
// https://cs.corp.google.com/chromeos_public/src/third_party/kernel/v4.14/include/uapi/linux/uhid.h?pv=1&l=180
// which has a size of uhidEventSize.
func (d *Device) readEvent() ([]byte, error) {
	if d.file == nil {
		return nil, errors.New("device has not been initialized")
	}

	buf := make([]byte, uhidEventSize)
	// Calls to file.Read block, this should be fixed.
	n, err := d.file.Read(buf)
	if err != nil {
		return buf, err
	}
	if n != uhidEventSize {
		return buf, errors.Errorf("unexpected number of bytes of UHID event; got %d, want %d", n, uhidEventSize)
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

// Dispatch must be called when an event needs to be handled. Be sure
// to implement some method of checking if the event you wish to
// handle was indeed the one handled.
func (d *Device) Dispatch(ctx context.Context) (ReadStatus, error) {
	if d.file == nil {
		return StatusOK, errors.New("device has not been initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	var buf []byte
	var err error

	go func() {
		buf, err = d.readEvent()
		close(done)
	}()

	select {
	case <-done:
		if err != nil {
			return StatusOK, errors.Wrap(err, "failed reading uhid event")
		}
		reader := bytes.NewReader(buf[:4]) // We just want to read the first uint32 for now
		var requestType uint32
		if err = binary.Read(reader, binary.LittleEndian, &requestType); err != nil {
			return StatusOK, errors.Wrap(err, "failed parsing uhid file data into request")
		}
		return StatusOK, d.processEvent(ctx, buf, requestType)
	case <-ctx.Done():
		return StatusNoEvent, nil
	}
}

// processEvent selects the correct function to handle the request
// sent by the kernel and runs it. It will return an error if the
// event us unrecognized.
func (d *Device) processEvent(ctx context.Context, buf []byte, requestType uint32) error {
	if f := d.EventHandlers[requestType]; f != nil {
		return f(ctx, d, buf)
	}
	return errors.Errorf("unknown event: %d", requestType)
}

// setDefaultHandlers assigns to d's EventHandlers map handlers that
// simply ignore the given event.
func (d *Device) setDefaultHandlers() {
	d.EventHandlers = map[uint32]eventHandler{
		Start:     defaultHandler,
		Stop:      defaultHandler,
		Open:      defaultHandler,
		Close:     defaultHandler,
		Output:    defaultHandler,
		GetReport: defaultHandler,
		SetReport: defaultHandler,
	}
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
		return errors.Errorf("device name too long: got %d want %d or shorter", len(uniq), 64)
	}
	copy(d.Data.uniq[:], uniq)
	return nil
}

// Bus returns the bus of this device.
func (d *Device) Bus() uint16 {
	return d.Data.bus
}

// VendorID returns the vendor id of this device.
func (d *Device) VendorID() uint32 {
	return d.Data.vendorID
}

// ProductID returns the product id of this device.
func (d *Device) ProductID() uint32 {
	return d.Data.productID
}

// createRequest returns a new uhidCreate2Request based on the data
// contained in deviceData.
func (dd *DeviceData) createRequest() uhidCreate2Request {
	return uhidCreate2Request{
		requestType:    Create2,
		name:           dd.name,
		phys:           dd.phys,
		uniq:           dd.uniq,
		descriptorSize: uint16(len(dd.descriptor)),
		bus:            dd.bus,
		vendorID:       dd.vendorID,
		productID:      dd.productID,
		version:        0,
		country:        0,
		descriptor:     dd.descriptor,
	}
}

// defaultHandler ignores the event that it is called to handle.
func defaultHandler(ctx context.Context, d *Device, buf []byte) error {
	return nil
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
	return fmt.Sprintf("%04X:%04X:%04X", d.Data.bus, d.Data.vendorID, d.Data.productID)
}
