// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package uhid

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"chromiumos/tast/errors"
	"chromiumos/tast/testing"
)

// NewDeviceFromRecording receives a file containing a hid recording recorded using
// hid-tools (https://gitlab.freedesktop.org/libevdev/hid-tools) and
// creates a device based on the information contained in it.
func NewDeviceFromRecording(ctx context.Context, file *os.File) (*Device, error) {
	dd := DeviceData{}
	scanner := bufio.NewScanner(file)
	var line string
	// The protocol used in hid recording files can be found here:
	// https://github.com/bentiss/hid-replay/blob/master/src/hid-replay.txt#L49
	i := 1
	for ; scanner.Scan(); line, i = scanner.Text(), i+1 {
		if len(line) == 0 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "E: ") {
			// We ignore comments, empty lines or event lines.
			continue
		}
		if len(line) < 4 {
			// If it's not a comment or an empty line it'll have a length of
			// at least 4.
			return nil, parsingError(ctx, "line is empty (line: %d)", line, file.Name(), i)
		}
		prefix, data := line[:3], line[3:]
		switch prefix {
		case "D: ":
			return nil, parsingError(ctx, "multi device recordings are not supported", line, file.Name(), i)
		case "N: ":
			copy(dd.name[:], data)
		case "I: ":
			var err error
			if dd.bus, dd.vendorID, dd.productID, err = parseInfo(ctx, data); err != nil {
				return nil, errors.Wrap(err, parsingError(ctx, "invalid info in recording file", line, file.Name(), i).Error())
			}
		case "P: ":
			copy(dd.phys[:], data)
		case "R: ":
			descriptor, err := parseArray(data)
			if err != nil {
				return nil, errors.Wrap(err, parsingError(ctx, "invalid descriptor in recording file", line, file.Name(), i).Error())
			}
			copy(dd.descriptor[:], descriptor[:])
		default:
			return nil, parsingError(ctx, "invalid line prefix in recording file", line, file.Name(), i)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, parsingError(ctx, "failure to parse", line, file.Name(), i).Error())
	}
	return &Device{Data: dd}, nil
}

// Replay receives a file containing a hid recording, parses it and
// injects the events into the given device. An error is returned if
// the recording file is invalid.
func (d *Device) Replay(ctx context.Context, file *os.File) error {
	if d.file == nil {
		return errors.New("device has not been initialized")
	}
	scanner := bufio.NewScanner(file)
	var line string
	i := 1
	sleep := time.Duration(0)
	for ; scanner.Scan(); line, i = scanner.Text(), i+1 {
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			// We ignore comments or empty lines.
			continue
		}
		if strings.HasPrefix(line, "D: ") {
			return parsingError(ctx, "multi device recordings are not supported", line, file.Name(), i)
		}
		if strings.HasPrefix(line, "E: ") {
			if len(line) < 15 {
				return parsingError(ctx, "unexpected format for event line", line, file.Name(), i)
			}
			line = line[3:]
			var err error
			var nextTimestamp time.Duration
			if nextTimestamp, err = parseTime(ctx, line); err != nil {
				return errors.Wrap(err, parsingError(ctx, "invalid recording file", line, file.Name(), i).Error())
			}
			if err := testing.Sleep(ctx, nextTimestamp-sleep); err != nil {
				return errors.Wrap(err, "failed while sleeping during replay")
			}
			sleep = nextTimestamp
			// The timestamp always occupies 13 spaces.
			line = line[14:]
			var data []byte
			if data, err = parseArray(line); err != nil {
				return err
			}
			if err = d.InjectEvent(data); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "failure to parse file (line: %d)", i)
	}
	return nil
}

// parseInfo returns the bus, vendor id and product id found in line.
func parseInfo(ctx context.Context, line string) (ddBus uint16, ddVendorID, ddProductID uint32, err error) {
	var bus uint64
	var vendorID uint64
	var productID uint64

	// The string should be in the format "<bus> <vendorID> <productID>"
	// where each number is separated by a white space.
	regex := regexp.MustCompile(`([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)`)
	info := regex.FindStringSubmatch(line)
	if len(info) == 0 {
		testing.ContextLogf(ctx, "Regexp: %q", regex)
		testing.ContextLogf(ctx, "String: %q", line)
		return 0, 0, 0, errors.New("failed to parse info with regexp")
	}

	// We ignore the first element which is the match corresponding to
	// the whole string.
	info = info[1:]
	for i, v := range []*uint64{&bus, &vendorID, &productID} {
		*v, err = strconv.ParseUint(info[i], 16, 16)
		if err != nil {
			return 0, 0, 0, errors.Wrapf(err, "failed to parse device info item number %d", i+1)
		}
	}

	ddBus = uint16(bus)
	ddVendorID = uint32(vendorID)
	ddProductID = uint32(productID)

	return
}

// parseTime returns a duration based on the received line that
// represents a time stamp. The line must be of the form
// "<seconds>.<microseconds>" where both seconds and microseconds are
// six digit long decimal numbers separated by a dot.
func parseTime(ctx context.Context, line string) (time.Duration, error) {
	var seconds uint64
	var microSeconds uint64
	var err error

	regex := regexp.MustCompile(`(\d{6})\.(\d{6})\s+.*`)
	times := regex.FindStringSubmatch(line)
	if len(times) == 0 {
		testing.ContextLogf(ctx, "Regexp: %q", regex)
		testing.ContextLogf(ctx, "String: %q", line)
		return 0, errors.New("failed to parse timestamp with regexp")
	}

	// We ignore the first element which is the match corresponding to
	// the whole string.
	times = times[1:]
	for i, v := range []*uint64{&seconds, &microSeconds} {
		*v, err = strconv.ParseUint(times[i], 10, 32)
		if err != nil {
			return 0, errors.Wrap(err, "failed parsing timestamp")
		}
	}

	return time.Duration(seconds)*time.Second + time.Duration(microSeconds)*time.Microsecond, nil
}

// parseArray returns the array represented by line as a byte array.
// Line should be of the form "<size> <d_1> <d_2> ... <d_size>" where
// size is the size of the returned array and d_i corresponds to
// element i in the returned array, separated by whitespace from the
// others at both sides.
func parseArray(line string) ([]byte, error) {
	dataFields := strings.Fields(line)
	if len(dataFields) == 0 {
		return nil, errors.New("empty array for parsing")
	}
	size, err := strconv.ParseUint(dataFields[0], 10, 16)
	if err != nil {
		return nil, errors.Wrap(err, "failed parsing event data array length")
	}
	if size != uint64(len(dataFields[1:])) {
		return nil, errors.Errorf("specified event data length does not match actual length; got %d, want %d", len(dataFields[1:]), size)
	}

	data := make([]byte, size)
	for i, v := range dataFields[1:] {
		n, err := strconv.ParseUint(v, 16, 8)
		if err != nil {
			return nil, errors.Wrap(err, "failed parsing event data element")
		}
		data[i] = byte(n)
	}

	return data, nil
}

// parsingError logs the line, line number and name of the file that
// caused the error and returns an error message with the given error
// message and line number.
func parsingError(ctx context.Context, errorMessage, line, fileName string, lineNumber int) error {
	testing.ContextLogf(ctx, "Failed to parse line %d of %s: %q", lineNumber, fileName, line)
	return errors.Errorf("%s (line: %d)", errorMessage, lineNumber)
}
