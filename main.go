package main

import (
	"bytes"
	_ "encoding/hex"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/usedbytes/bot_matrix/datalink"
	"github.com/usedbytes/bot_matrix/datalink/spiconn"
)

const AckEndpoint = 0x1
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

func calcCRC(data []byte) (uint32, error) {
	if len(data) % 4 != 0 {
		return 0, fmt.Errorf("Data length must be multiple of 4")
	}

	word := binary.LittleEndian.Uint32(data[0:4])
	crc := STM32CRC32(0xffffffff, word)
	for i := 4; i < len(data); i += 4 {
		word = binary.LittleEndian.Uint32(data[i:i + 4])
		crc = STM32CRC32(crc, word)
	}

	return crc, nil
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

	crc, err := calcCRC(r.Data)
	if err != nil {
		return err
	}

	if crc != r.CRC {
		return fmt.Errorf("CRC mismatch in read response. %x != %x", crc, r.CRC)
	}

	return nil
}

const EraseEndpoint = 0x3
type ErasePkt struct {
	Address uint32
}

func (e *ErasePkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: EraseEndpoint,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, e.Address)
	pkt.Data = buf.Bytes()

	return pkt
}

const WriteEndpoint = 0x4
type WritePkt struct {
	Address uint32
	Len uint32
	CRC uint32
	Data []byte
}

func IsCRCError(e error) bool {
	return strings.Contains(e.Error(), "CRC")
}

func (w *WritePkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: WriteEndpoint,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, w.Address)
	binary.Write(buf, binary.LittleEndian, w.Len)
	binary.Write(buf, binary.LittleEndian, w.CRC)
	buf.Write(w.Data)

	pkt.Data = buf.Bytes()

	return pkt
}

const GoEndpoint = 0x7
type GoPkt struct {
	Address uint32
}

func (g *GoPkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: GoEndpoint,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, g.Address)

	pkt.Data = buf.Bytes()

	return pkt
}

const QueryEndpoint = 0x8
const QueryParamMaxTransfer = 0x1

type QueryPkt struct {
	Parameter uint32
}

func (q *QueryPkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: QueryEndpoint,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, q.Parameter)

	pkt.Data = buf.Bytes()

	return pkt
}

const QueryRespEndpoint = 0x9
type QueryRespPkt struct {
	Parameter uint32
	Value uint32
}

func (r *QueryRespPkt) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.LittleEndian, &r.Parameter)
	binary.Read(buf, binary.LittleEndian, &r.Value)

	return nil
}

type FlashCtx struct {
	c datalink.Transactor
}

func sync(ctx *FlashCtx) error {
	ctx.c.Transact([]datalink.Packet{
		datalink.Packet{2, []byte{ 0, 0, 0, 0, 1, 2, 3, 4 }},
	})

	for i := 0; i < 64; i++ {
		ret, _ := ctx.c.Transact([]datalink.Packet{
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
			datalink.Packet{0, []byte{}},
		})
		i++

		for _, pkt := range ret {
			switch pkt.Endpoint {
			/*
			case ErrorEndpoint:
				e := new(ErrorPkt)
				err = e.UnmarshalBinary(pkt.Data)
				if err != nil {
					return err
				}
				return e
			*/
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

func readData(ctx *FlashCtx, address, length uint32) (*ReadRespPkt, error) {
	req := ReadReqPkt{
		Address: address,
		Len: length,
	}

	_, err := ctx.c.Transact([]datalink.Packet{
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
		ret, err := ctx.c.Transact([]datalink.Packet{
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

func waitForAck(ctx *FlashCtx, timeout time.Duration) error {
	loops := timeout / (5 * time.Millisecond)

	for i := 0; i < int(loops); i++ {
		time.Sleep(5 * time.Millisecond)
		ret, err := ctx.c.Transact([]datalink.Packet{
			datalink.Packet{0, []byte{}},
		})
		if (err != nil) && !IsCRCError(err) {
			return err
		}

		for _, pkt := range ret {
			switch pkt.Endpoint {
			case ErrorEndpoint:
				e := new(ErrorPkt)
				err = e.UnmarshalBinary(pkt.Data)
				if err != nil {
					return err
				}
				return e
			case AckEndpoint:
				return nil
			}
		}
	}

	return fmt.Errorf("Timeout waiting for Ack.")
}

func erasePage(ctx *FlashCtx, address uint32) error {
	req := ErasePkt{
		Address: address,
	}

	if (address & uint32(1024 - 1)) != 0 {
		return fmt.Errorf("Erase address must be 1 kB page-aligned.");
	}

	ret, err := ctx.c.Transact([]datalink.Packet{
		req.Packet(),
	})
	if err != nil {
		return err
	}
	for _, pkt := range ret {
		switch pkt.Endpoint {
		case ErrorEndpoint:
			e := new(ErrorPkt)
			err = e.UnmarshalBinary(pkt.Data)
			if err != nil {
				return err
			}
			return e
		}
	}

	err = waitForAck(ctx, 50 * time.Millisecond)
	if err != nil {
		return err
	}

	dat, err := readData(ctx, address, 512)
	if err != nil {
		return err
	}
	for _, x := range dat.Data {
		if x != 0xff {
			return fmt.Errorf("Erase unsuccessful.")
		}
	}

	return nil
}

func jumpTo(ctx *FlashCtx, address uint32) error {
	req := GoPkt{
		Address: address,
	}

	ret, err := ctx.c.Transact([]datalink.Packet{
		req.Packet(),
	})
	if err != nil {
		return err
	}
	for _, pkt := range ret {
		switch pkt.Endpoint {
		case ErrorEndpoint:
			e := new(ErrorPkt)
			err = e.UnmarshalBinary(pkt.Data)
			if err != nil {
				return err
			}
			return e
		}
	}

	return nil
}

func writeData(ctx *FlashCtx, address uint32, data []byte, verify bool) error {
	req := WritePkt{
		Address: address,
		Len: uint32(len(data)),
		Data: data,
	}

	crc, err := calcCRC(data)
	if err != nil {
		return err
	}
	req.CRC = crc

	ret, err := ctx.c.Transact([]datalink.Packet{
		req.Packet(),
	})
	if err != nil {
		return err
	}
	for _, pkt := range ret {
		switch pkt.Endpoint {
		case ErrorEndpoint:
			e := new(ErrorPkt)
			err = e.UnmarshalBinary(pkt.Data)
			if err != nil {
				return err
			}
			return e
		}
	}

	err = waitForAck(ctx, 50 * time.Millisecond)
	if err != nil {
		return err
	}

	if verify {
		dat, err := readData(ctx, address, uint32(len(data)))
		if err != nil {
			return err
		}
		if !bytes.Equal(dat.Data, data) {
			return fmt.Errorf("Verify failed.")
		}
	}

	return nil
}

func doQuery(ctx *FlashCtx, parameter uint32) (uint32, error) {
	req := QueryPkt{
		Parameter: parameter,
	}

	_, err := ctx.c.Transact([]datalink.Packet{
		req.Packet(),
	})
	if err != nil {
		return 0, err
	}

	ntries := 8
	for i := 0; i < ntries; i++ {
		ret, err := ctx.c.Transact([]datalink.Packet{
			datalink.Packet{0, []byte{}},
		})
		if err != nil {
			return 0, err
		}

		for _, pkt := range ret {
			switch pkt.Endpoint {
			case ErrorEndpoint:
				e := new(ErrorPkt)
				err = e.UnmarshalBinary(pkt.Data)
				if err != nil {
					return 0, err
				}
				return 0, e
			case QueryRespEndpoint:
				resp := new(QueryRespPkt)
				err = resp.UnmarshalBinary(pkt.Data)
				if err != nil {
					return 0, err
				}
				if resp.Parameter != parameter {
					return 0, fmt.Errorf("Received wrong query response");
				}
				return resp.Value, nil
			}
		}
	}

	return 0, fmt.Errorf("Read timeout.")
}

func main() {
	c, err := spiconn.NewSPIConn("/dev/spidev0.0")
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx := new(FlashCtx)
	ctx.c = c

	err = sync(ctx)
	if err != nil {
		fmt.Println("sync err:", err)
	}

	maxTransfer, err := doQuery(ctx, QueryParamMaxTransfer)
	if err != nil {
		fmt.Println("query err:", err)
	}
	fmt.Println("Max transfer size: ", maxTransfer)


	/*
	err = erasePage(ctx.c, 0x0800C000);
	fmt.Println(err)

	err = writeData(ctx.c, 0x0800C000, bytes.Repeat([]byte{1, 2, 3, 4}, 128), true);
	fmt.Println(err)
	*/


	time.Sleep(1 * time.Second)
	jumpTo(ctx, 0x0800C000)

	return

	t := time.NewTicker(500 * time.Millisecond)
	for _ = range t.C {

		//start := time.Now()
		/*
		resp, err := readData(ctx.c, 0x0800C000, 512)
		if err != nil {
			fmt.Println(err)
			err = sync(ctx.c)
			if err != nil {
				fmt.Println("sync err:", err)
			}
		} else {
			fmt.Printf("Read %d bytes.\n", resp.Len)
			fmt.Println(time.Since(start))
		}
		*/
	}
}
