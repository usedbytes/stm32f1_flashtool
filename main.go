package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/usedbytes/bot_matrix/datalink"
	"github.com/usedbytes/bot_matrix/datalink/spiconn"
)

const ErrorEndpoint = 0xff
type ErrorPkt struct {
	ID uint8
	Err string
}

func (e *ErrorPkt) Error() string {
	return fmt.Sprintf("id: %d - %s", e.ID, e.Err)
}

func (e *ErrorPkt) UnmarshalBinary(data []byte) error {
	e.ID = data[0]
	e.Err = string(data[4:])

	return nil
}

func sync(c datalink.Transactor) error {
	c.Transact([]datalink.Packet{
		datalink.Packet{2, []byte{ 0, 0, 0, 0, 1, 2, 3, 4 }},
	})

	for i := 0; i < 5; i++ {
		ret, err := c.Transact([]datalink.Packet{
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
		})
		i++

		for _, pkt := range ret {
			switch pkt.Endpoint {
			case ErrorEndpoint:
				e := new(ErrorPkt)
				err = e.UnmarshalBinary(pkt.Data)
				if err != nil {
					return err
				}
				return e
			case 2:
				if !bytes.Equal(pkt.Data[4:8], []byte{1, 2, 3, 4}) {
					return fmt.Errorf("Bad sync cookie.")
				}
				return nil
			}
		}
	}

	return fmt.Errorf("Sync took too long.")
}

func main() {

	c, err := spiconn.NewSPIConn("/dev/spidev0.0")
	if err != nil {
		fmt.Println(err)
		return
	}


	i := byte(0)
	t := time.NewTicker(500 * time.Millisecond)
	for _ = range t.C {
		ret, err := c.Transact([]datalink.Packet{
			datalink.Packet{1, []byte{ i }},
		})
		i ^= 1

		if err != nil {
			fmt.Println(err)
		} else {
			for _, pkt := range ret {
				switch pkt.Endpoint {
				case ErrorEndpoint:
					var e ErrorPkt
					err = (&e).UnmarshalBinary(pkt.Data)
					if err != nil {
						fmt.Println(err)
					}
					fmt.Println(e.Error())
				}
			}

		}

		err = sync(c)
		if err != nil {
			fmt.Println("sync err:", err)
		}
	}
}
