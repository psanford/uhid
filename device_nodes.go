// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package uhid

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"chromiumos/tast/errors"
	"chromiumos/tast/testing"
)

// devicePath returns the path corresponding to this device that
// exists in /sys/bus/hid/devices/.
// An example of a possible device path is
// /sys/bus/hid/devices/0003:046D:C31C.0018 where 0003 is the bus,
// 046D is the vendor id and C31C is the product id. 0018 is a unique
// number given in case multiple devices exist with the same bus and
// ids. In the case of this library we choose to take the path of the
// most recently created device. That is, the one with the highest
// unique number.
func devicePath(infoString string) (string, error) {
	const devicesDirectory = "/sys/bus/hid/devices/"

	files, err := ioutil.ReadDir(devicesDirectory)
	if err != nil {
		return "", err
	}
	devicePath := ""
	newestDeviceID := -1
	for _, f := range files {
		var currentID int
		if currentID, err = deviceID(f.Name()); err != nil {
			return "", err
		}
		if currentID > newestDeviceID && strings.HasPrefix(f.Name(), infoString) {
			newestDeviceID = currentID
			devicePath = f.Name()
		}
	}
	if devicePath == "" {
		return "", errors.Errorf("device %s hasn't been created", infoString)
	}
	return path.Join(devicesDirectory, devicePath), nil
}

// hidrawNodes returns the hidraw nodes that exist under
// <path>/hidraw.  Because the hidraw directory takes some time to be
// createad we poll for it.
func hidrawNodes(ctx context.Context, devicePath string) ([]string, error) {
	const hidrawDir = "hidraw"

	err := testing.Poll(ctx, func(ctx context.Context) error {
		directories, err := ioutil.ReadDir(devicePath)
		if err != nil {
			return err
		}
		for _, d := range directories {
			if d.Name() == hidrawDir {
				return nil
			}
		}
		return errors.New("hidraw directory was not created")
	}, &testing.PollOptions{Timeout: 10 * time.Second})
	if err != nil {
		return nil, errors.Wrap(err, "failed waiting for hidraw directory")
	}

	devicePath = path.Join(devicePath, hidrawDir)
	files, err := ioutil.ReadDir(devicePath)
	if err != nil {
		return nil, err
	}
	return hidrawPaths(files), nil
}

// eventNodes returns the event nodes under <path>/input/input*.
// A device can have multiple directories like this. For example,
// a dualshock 3 controller will have <path>/input/input<i> and
// <path>/input/input<i+1> which represent the controller and
// its motion sensors.
func eventNodes(devicePath string) ([]string, error) {
	eventNodes := make([]string, 0)
	directories, err := ioutil.ReadDir(path.Join(devicePath, "input"))
	if err != nil {
		return nil, err
	}
	for _, d := range directories {
		if strings.HasPrefix(d.Name(), "input") {
			eventNode, err := eventNode(path.Join(devicePath, "input", d.Name()))
			if err != nil {
				return nil, err
			}
			eventNodes = append(eventNodes, eventNode)
		}
	}
	if len(eventNodes) == 0 {
		return nil, errors.New("the created device has no event nodes")
	}
	return eventNodes, nil
}

// deviceID returns the unique ID belonging to the device represented by the
// directory in path.
func deviceID(path string) (int, error) {
	id, err := strconv.ParseInt(filepath.Ext(path)[1:], 16, 0)
	if err != nil {
		return -1, errors.New("the given path is not a sysfs device path")
	}
	return int(id), nil
}

// hidrawPaths returns the file names of the files in files prepended
// with "/dev/" which creates their absolute path. It filters out of
// files the none hidraw files.
func hidrawPaths(files []os.FileInfo) []string {
	paths := make([]string, 0)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "hidraw") {
			paths = append(paths, "/dev/"+f.Name())
		}
	}
	return paths
}

// eventNode gets the event* node that exists inside path and prepends
// to it "/dev/input/" to create its absolute path.
func eventNode(devicePath string) (string, error) {
	files, err := ioutil.ReadDir(devicePath)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "event") {
			return path.Join("dev/input", f.Name()), nil
		}
	}
	return "", nil
}
