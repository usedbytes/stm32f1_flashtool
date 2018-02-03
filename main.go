package main

import (
	"bytes"
	_ "encoding/hex"
	"encoding/binary"
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

const ReadReqEndpoint = 0x5
type ReadReqPkt struct {
	Address uint32
	Len uint32
}

func (r *ReadReqPkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: ReadReqEndpoint,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, r.Address)
	binary.Write(buf, binary.LittleEndian, r.Len)
	pkt.Data = buf.Bytes()

	return pkt
}

const ReadRespEndpoint = 0x6
type ReadRespPkt struct {
	Address uint32
	Len uint32
	CRC uint32
	Data []byte
}

// CRC Implementation from Clive One https://community.st.com/thread/18626
var Table []uint32 = []uint32{ // Nibble lookup table for 0x04C11DB7 polynomial
	0x00000000,0x04C11DB7,0x09823B6E,0x0D4326D9,0x130476DC,0x17C56B6B,0x1A864DB2,0x1E475005,
	0x2608EDB8,0x22C9F00F,0x2F8AD6D6,0x2B4BCB61,0x350C9B64,0x31CD86D3,0x3C8EA00A,0x384FBDBD,
}

func STM32CRC32(crc, data uint32) uint32 {
	crc ^= data; // Apply all 32-bits

	// Process 32-bits, 4 at a time, or 8 rounds
	crc = (crc << 4) ^ Table[crc >> 28] // Assumes 32-bit reg, masking index to 4-bits
	crc = (crc << 4) ^ Table[crc >> 28] //  0x04C11DB7 Polynomial used in STM32
	crc = (crc << 4) ^ Table[crc >> 28]
	crc = (crc << 4) ^ Table[crc >> 28]
	crc = (crc << 4) ^ Table[crc >> 28]
	crc = (crc << 4) ^ Table[crc >> 28]
	crc = (crc << 4) ^ Table[crc >> 28]
	crc = (crc << 4) ^ Table[crc >> 28]

	return crc
}

func (r *ReadRespPkt) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.LittleEndian, &r.Address)
	binary.Read(buf, binary.LittleEndian, &r.Len)
	binary.Read(buf, binary.LittleEndian, &r.CRC)

	r.Data = make([]byte, r.Len)
	n := copy(r.Data, data[12:])
	if uint32(n) != r.Len {
		return fmt.Errorf("Short data (%d) in read response.", n)
	}

	word := binary.LittleEndian.Uint32(r.Data[0:4])
	crc := STM32CRC32(0xffffffff, word)
	for i := uint32(4); i < r.Len; i += 4 {
		word = binary.LittleEndian.Uint32(r.Data[i:i + 4])
		crc = STM32CRC32(crc, word)
	}

	if crc != r.CRC {
		return fmt.Errorf("CRC mismatch in read response. %x != %x", crc, r.CRC)
	}

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
			/*
			default:
				fmt.Println(pkt)
				fmt.Println(hex.Dump(pkt.Data))
			*/
			}
		}
	}

	return fmt.Errorf("Sync took too long.")
}

func readData(c datalink.Transactor, address, length uint32) (*ReadRespPkt, error) {
	req := ReadReqPkt{
		Address: address,
		Len: length,
	}

	_, err := c.Transact([]datalink.Packet{
		req.Packet(),
	})
	if err != nil {
		return nil, err
	}

	ntries := ((length + 31) / 32) * 2
	if ntries < 8 {
		ntries = 8
	}
	for i := uint32(0); i < ntries; i++ {
		ret, err := c.Transact([]datalink.Packet{
			datalink.Packet{0, []byte{}},
		})
		if err != nil {
			return nil, err
		}

		for _, pkt := range ret {
			switch pkt.Endpoint {
			case ErrorEndpoint:
				e := new(ErrorPkt)
				err = e.UnmarshalBinary(pkt.Data)
				if err != nil {
					return nil, err
				}
				return nil, e
			case ReadRespEndpoint:
				resp := new(ReadRespPkt)
				err = resp.UnmarshalBinary(pkt.Data)
				if err != nil {
					return nil, err
				}
				return resp, nil
			}
		}
	}

	return nil, fmt.Errorf("Read timeout.")
}

func main() {

	c, err := spiconn.NewSPIConn("/dev/spidev0.0")
	if err != nil {
		fmt.Println(err)
		return
	}


	t := time.NewTicker(500 * time.Millisecond)
	for _ = range t.C {

		start := time.Now()
		resp, err := readData(c, 0x08002000, 512)
		if err != nil {
			fmt.Println(err)
			err = sync(c)
			if err != nil {
				fmt.Println("sync err:", err)
			}
		} else {
			fmt.Printf("Read %d bytes.\n", resp.Len)
			fmt.Println(time.Since(start))
		}
	}
}
