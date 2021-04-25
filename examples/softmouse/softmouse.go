// This package is a partial port of the kernel's samples/uhid/uhid-example.c.
// It implements a soft mouse movable from the terminal via uhid.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/pkg/term"
	"github.com/psanford/uhid"
)

const BusUSB = 0x03

func main() {

	err := run()
	if err != nil {
		panic(err)
	}
}

var rdesc = []byte{
	0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
	0x09, 0x02, /* USAGE (Mouse) */
	0xa1, 0x01, /* COLLECTION (Application) */
	0x09, 0x01, /* USAGE (Pointer) */
	0xa1, 0x00, /* COLLECTION (Physical) */
	0x85, 0x01, /* REPORT_ID (1) */
	0x05, 0x09, /* USAGE_PAGE (Button) */
	0x19, 0x01, /* USAGE_MINIMUM (Button 1) */
	0x29, 0x03, /* USAGE_MAXIMUM (Button 3) */
	0x15, 0x00, /* LOGICAL_MINIMUM (0) */
	0x25, 0x01, /* LOGICAL_MAXIMUM (1) */
	0x95, 0x03, /* REPORT_COUNT (3) */
	0x75, 0x01, /* REPORT_SIZE (1) */
	0x81, 0x02, /* INPUT (Data,Var,Abs) */
	0x95, 0x01, /* REPORT_COUNT (1) */
	0x75, 0x05, /* REPORT_SIZE (5) */
	0x81, 0x01, /* INPUT (Cnst,Var,Abs) */
	0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
	0x09, 0x30, /* USAGE (X) */
	0x09, 0x31, /* USAGE (Y) */
	0x09, 0x38, /* USAGE (WHEEL) */
	0x15, 0x81, /* LOGICAL_MINIMUM (-127) */
	0x25, 0x7f, /* LOGICAL_MAXIMUM (127) */
	0x75, 0x08, /* REPORT_SIZE (8) */
	0x95, 0x03, /* REPORT_COUNT (3) */
	0x81, 0x06, /* INPUT (Data,Var,Rel) */
	0xc0,       /* END_COLLECTION */
	0xc0,       /* END_COLLECTION */
	0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
	0x09, 0x06, /* USAGE (Keyboard) */
	0xa1, 0x01, /* COLLECTION (Application) */
	0x85, 0x02, /* REPORT_ID (2) */
	0x05, 0x08, /* USAGE_PAGE (Led) */
	0x19, 0x01, /* USAGE_MINIMUM (1) */
	0x29, 0x03, /* USAGE_MAXIMUM (3) */
	0x15, 0x00, /* LOGICAL_MINIMUM (0) */
	0x25, 0x01, /* LOGICAL_MAXIMUM (1) */
	0x95, 0x03, /* REPORT_COUNT (3) */
	0x75, 0x01, /* REPORT_SIZE (1) */
	0x91, 0x02, /* Output (Data,Var,Abs) */
	0x95, 0x01, /* REPORT_COUNT (1) */
	0x75, 0x05, /* REPORT_SIZE (5) */
	0x91, 0x01, /* Output (Cnst,Var,Abs) */
	0xc0, /* END_COLLECTION */
}

func run() error {
	d, err := uhid.NewDevice("go-test-uhid-device-go", rdesc)
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

	go func() {
		for evt := range evtChan {
			if evt.Err != nil {
				log.Fatalf("got evt err: %s", err)
			}
			log.Printf("got evt: %d", evt.Type)
		}
	}()

	t, err := term.Open("/dev/tty")
	if err != nil {
		return fmt.Errorf("open terminal err: %w", err)
	}
	defer t.Close()

	for {
		ascii, keyCode, err := getChar(t)
		if err != nil {
			return err
		}

		if ascii == 'q' {
			break
		}

		switch keyCode {
		case ArrowUp:
			log.Println("send ArrowUp")
			err = sendEvent(d, 0, -20)
			if err != nil {
				log.Printf("send Up err: %s\n", err)
				return err
			}
		case ArrowDown:
			log.Println("send ArrowDown")
			err = sendEvent(d, 0, 20)
			if err != nil {
				log.Printf("send Up err: %s\n", err)
				return err
			}
		case ArrowRight:
			log.Println("send ArrowRight")
			err = sendEvent(d, 20, 0)
			if err != nil {
				log.Printf("send Up err: %s\n", err)
				return err
			}
		case ArrowLeft:
			log.Println("send ArrowLeft")
			err = sendEvent(d, -20, 0)
			if err != nil {
				log.Printf("send Up err: %s\n", err)
				return err
			}
		}
	}

	return nil
}

func sendEvent(d *uhid.Device, horizontal, vertical int8) error {
	evt := uhid.Input2Request{
		RequestType: uhid.Input2,
	}

	evt.Data[0] = 0x01

	// evt.Data[1] keyboard
	evt.Data[2] = byte(horizontal)
	evt.Data[3] = byte(vertical)

	// evt.Data[4] mouse

	evt.DataSize = 5

	return d.WriteEvent(evt)
}

const (
	ArrowUp    = 38
	ArrowDown  = 40
	ArrowRight = 39
	ArrowLeft  = 37
)

// Returns either an ascii code, or (if input is an arrow) a Javascript key code.
func getChar(t *term.Term) (ascii rune, keyCode int, err error) {
	term.RawMode(t)
	defer t.Restore()
	bytes := make([]byte, 3)

	var numRead int
	numRead, err = t.Read(bytes)
	if err != nil {
		return
	}
	if numRead == 3 && bytes[0] == 27 && bytes[1] == 91 {
		// Three-character control sequence, beginning with "ESC-[".

		// Since there are no ASCII codes for arrow keys, we use
		// Javascript key codes.
		if bytes[2] == 65 {
			keyCode = ArrowUp
		} else if bytes[2] == 66 {
			keyCode = ArrowDown
		} else if bytes[2] == 67 {
			keyCode = ArrowRight
		} else if bytes[2] == 68 {
			keyCode = ArrowLeft
		}
	} else if numRead == 1 {
		ascii = rune(bytes[0])
	} else {
		// Two characters read??
	}
	return
}
