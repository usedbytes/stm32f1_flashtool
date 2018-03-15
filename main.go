package main

import (
	"bytes"
	_ "encoding/hex"
	"encoding/binary"
	"fmt"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"strconv"
	"time"

	"gopkg.in/cheggaaa/pb.v1"
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
const QueryDefaultUserAddr = 0x2

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

const ResetEndpoint = 0xfe
type ResetPkt struct { }

func (r *ResetPkt) Packet() datalink.Packet {
	pkt := datalink.Packet{
		Endpoint: ResetEndpoint,
	}

	return pkt
}

type FlashCtx struct {
	c datalink.Transactor

	preReset bool
	maxTransfer uint32
	read bool
	readCfg readCfg
	erase bool
	eraseCfg eraseCfg
	autoErase bool
	write bool
	writeCfg writeCfg
	verify bool
	retries uint
	reset bool
	jump bool
	jumpCfg jumpCfg

	data []byte
}
type operation func(ctx *FlashCtx) error

func (ctx *FlashCtx) retry(op operation) error {
	for i := uint(0); i < ctx.retries; i++ {
		err := op(ctx)
		if err == nil {
			return nil
		}

		fmt.Fprintln(os.Stderr, err)
	}

	return fmt.Errorf("Too many failures.")
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func doRead(ctx *FlashCtx) error {
	length := ctx.readCfg.length
	lastAddress := ctx.readCfg.address + length

	fmt.Fprintf(os.Stderr, "Read %d bytes from 0x%08x\n", length, ctx.readCfg.address)

	buf := new(bytes.Buffer)

	bar := pb.New(int(lastAddress - ctx.readCfg.address))
	bar.ManualUpdate = true
	bar.Start()

	for address := ctx.readCfg.address; address < lastAddress; address += ctx.maxTransfer {
		chunk := min(lastAddress - address, ctx.maxTransfer)
		b, err := readData(ctx, address, chunk)
		if err != nil {
			return err
		}
		buf.Write(b.Data)

		bar.Add(int(chunk))
		bar.Update()
	}

	bar.Finish()

	ctx.data = buf.Bytes()

	return nil
}

const flashPageSize = 1024
func doErase(ctx *FlashCtx) error {
	length := ctx.eraseCfg.length
	lastAddress := ctx.eraseCfg.address + length

	if length % flashPageSize != 0 {
		fmt.Fprintf(os.Stderr, "Erase length must be multiple of page size (%d)\n", flashPageSize)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Erase %d bytes from 0x%08x\n", length, ctx.eraseCfg.address)

	bar := pb.New(int(lastAddress - ctx.eraseCfg.address))
	bar.ManualUpdate = true
	bar.Start()

	for address := ctx.eraseCfg.address; address < lastAddress; address += flashPageSize {
		err := erasePage(ctx, address)
		if err != nil {
			return err
		}

		bar.Add(flashPageSize)
		bar.Update()
	}

	bar.Finish()

	return nil
}

func roundUp(length, to uint32) uint32 {
	return (length + (to - 1)) & ^(to - 1);
}

func doWrite(ctx *FlashCtx) error {
	if ctx.autoErase {
		ctx.eraseCfg.address = ctx.writeCfg.address
		ctx.eraseCfg.length = roundUp(uint32(len(ctx.data)), flashPageSize)
		err := doErase(ctx)
		if err != nil {
			return err
		}
	}

	length := uint32(len(ctx.data))
	if length % 4 != 0 {
		length = roundUp(uint32(len(ctx.data)), 4)
		ctx.data = append(ctx.data, bytes.Repeat([]byte{0}, int(length) - len(ctx.data))...)
	}
	lastAddress := ctx.writeCfg.address + length

	s := ""
	if ctx.verify {
		s = "(and verify) "
	}
	fmt.Fprintf(os.Stderr, "Write %s%d bytes to 0x%08x\n", s, length, ctx.writeCfg.address)

	bar := pb.New(int(lastAddress - ctx.writeCfg.address))
	bar.ManualUpdate = true
	bar.Start()

	idx := uint32(0)
	for address := ctx.writeCfg.address; address < lastAddress; address, idx = address + ctx.maxTransfer, idx + ctx.maxTransfer {
		chunk := min(lastAddress - address, ctx.maxTransfer)

		err := writeData(ctx, address, ctx.data[idx:idx + chunk], ctx.verify)
		if err != nil {
			return err
		}

		bar.Add(int(chunk))
		bar.Update()
	}

	bar.Finish()

	return nil
}

func doReset(ctx *FlashCtx) error {
	req := ResetPkt{ }

	fmt.Fprintf(os.Stderr, "Resetting...\n")

	ret, err := ctx.c.Transact([]datalink.Packet{
		/*
		 * Send some empty packets first, to make sure there's a free
		 * packet to receive the reset request.
		 */
		datalink.Packet{0, []byte{}},
		datalink.Packet{0, []byte{}},
		datalink.Packet{0, []byte{}},
		datalink.Packet{0, []byte{}},
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

func doJump(ctx *FlashCtx) error {

	fmt.Fprintf(os.Stderr, "Jump to 0x%08x...\n", ctx.jumpCfg.address)

	return jumpTo(ctx, ctx.jumpCfg.address)
}

func sync(ctx *FlashCtx) error {
	ctx.c.Transact([]datalink.Packet{
		datalink.Packet{2, []byte{ 0, 0, 0, 0, 1, 2, 3, 4 }},
	})

	for i := 0; i < 128; i++ {
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

	if (address & uint32(flashPageSize - 1)) != 0 {
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

type CmdLine struct {
	preReset bool
	dev string
	baud uint
	readStr string
	eraseStr string
	autoErase bool
	writeStr string
	verify bool
	retries uint
	reset bool
	jumpStr string
}

var cmdLine CmdLine

type readCfg struct {
	address uint32
	length uint32
	file io.Writer
}

func (c *readCfg) UnmarshalText(text []byte) error {
	str := string(text)

	parts := strings.Split(str, ":")
	if len(parts) != 3 {
		return fmt.Errorf("Read command must be of the form: address:length:file")
	}

	addr, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return err
	}
	c.address = uint32(addr)

	length, err := strconv.ParseUint(parts[1], 0, 32)
	if err != nil {
		return err
	}
	c.length = uint32(length)

	if parts[2] == "-" {
		c.file = os.Stdout
	} else {
		file, err := os.Create(parts[2])
		if err != nil {
			return err
		}
		c.file = file
	}

	return nil
}

type eraseCfg struct {
	address uint32
	length uint32
}

func (c *eraseCfg) UnmarshalText(text []byte) error {
	str := string(text)

	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return fmt.Errorf("Erase command must be of the form: address:length")
	}

	addr, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return err
	}
	c.address = uint32(addr)

	length, err := strconv.ParseUint(parts[1], 0, 32)
	if err != nil {
		return err
	}
	c.length = uint32(length)

	return nil
}

type writeCfg struct {
	address uint32
	file io.Reader
}

func (c *writeCfg) UnmarshalText(text []byte) error {
	str := string(text)

	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return fmt.Errorf("Write command must be of the form: address:length:file")
	}

	addr, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return err
	}
	c.address = uint32(addr)

	if parts[1] == "-" {
		c.file = os.Stdin
	} else {
		file, err := os.Open(parts[1])
		if err != nil {
			return err
		}
		c.file = file
	}

	return nil
}

type jumpCfg struct {
	address uint32
}

func (c *jumpCfg) UnmarshalText(text []byte) error {
	str := string(text)

	addr, err := strconv.ParseUint(str, 0, 32)
	if err != nil {
		return err
	}
	c.address = uint32(addr)

	return nil
}

func init() {
	// -d device (/dev/spidev0.0)
	//     The SPI device to use
	// -b clk (default 1 MHz)
	//     SPI clock rate
	// -r address:length:file
	//     Read from address into file
	// -e [address:length]
	//     Erase length bytes from address
	// -E
	//     Erase before write (valid only in conjunction with 'w')
	// -w address:file
	// -v verify
	//     Read back written data to verify
	// -n retries (default 5)
	//     Allow operations to be retried in the case of an error.
	// -r
	//     Reset when done
	// -g address
	//     Jump to address

	flag.BoolVar(&cmdLine.preReset, "p", false, "Send reset (and don't check) before anything else.")
	flag.StringVar(&cmdLine.dev, "d", "/dev/spidev0.0", "The SPI device to use.")
	flag.UintVar(&cmdLine.baud, "b", 1000000, "The SPI clock speed.")
	flag.StringVar(&cmdLine.readStr, "r", "", "address:length:file - Read length bytes from address into file.")
	flag.StringVar(&cmdLine.eraseStr, "e", "", "[address:length] - Erase length bytes from address.")
	flag.BoolVar(&cmdLine.autoErase, "E", false, "Erase before write.")
	flag.StringVar(&cmdLine.writeStr, "w", "", "address:length:file - Write length bytes from file into address.")
	flag.BoolVar(&cmdLine.verify, "v", false, "Verify after write.")
	flag.UintVar(&cmdLine.retries, "n", 5, "Number of times to allow operations to be retried in the case of an error.")
	flag.BoolVar(&cmdLine.reset, "R", false, "Reset when done.")
	flag.StringVar(&cmdLine.jumpStr, "g", "", "address - Jump to address.")
}

func parseCmdline(ctx *FlashCtx) error {
	flag.Parse()

	ctx.preReset = cmdLine.preReset

	c, err := spiconn.NewSPIConn(cmdLine.dev)
	if err != nil {
		return err
	}
	ctx.c = c

	if cmdLine.readStr != "" {
		err = (ctx.readCfg).UnmarshalText([]byte(cmdLine.readStr))
		if err != nil {
			return err
		}
		ctx.read = true
	}

	if cmdLine.eraseStr != "" {
		err = (ctx.eraseCfg).UnmarshalText([]byte(cmdLine.eraseStr))
		if err != nil {
			return err
		}
		ctx.erase = true
	}

	ctx.autoErase = cmdLine.autoErase

	if cmdLine.writeStr != "" {
		err = (ctx.writeCfg).UnmarshalText([]byte(cmdLine.writeStr))
		if err != nil {
			return err
		}
		ctx.write = true
	}

	ctx.verify = cmdLine.verify

	ctx.retries = cmdLine.retries

	ctx.reset = cmdLine.reset

	if cmdLine.jumpStr != "" {
		err = (ctx.jumpCfg).UnmarshalText([]byte(cmdLine.jumpStr))
		if err != nil {
			return err
		}
		ctx.jump = true
	}

	return nil
}

func main() {
	ctx := new(FlashCtx)

	err := parseCmdline(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if ctx.preReset {
		doReset(ctx)
		time.Sleep(100 * time.Millisecond)
	}

	maxTransfer, err := doQuery(ctx, QueryParamMaxTransfer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get maxTransfer failed: ", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Max transfer size: ", maxTransfer)
	ctx.maxTransfer = maxTransfer

	defaultAddr, err := doQuery(ctx, QueryDefaultUserAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get defaultUserAddr failed: ", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Default user address: 0x%08x\n", defaultAddr)

	err = sync(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Init failed:", err)
		os.Exit(1)
	}

	// Do each step in order:
	// 1. Read
	if ctx.read {
		err = ctx.retry(doRead)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx.readCfg.file.Write(ctx.data)
		if f, ok := ctx.readCfg.file.(*os.File); ok {
			f.Close()
		}
	}

	// 2. Erase
	if ctx.erase {
		err = ctx.retry(doErase)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// 3. Write
	if ctx.write {
		ctx.data, err = ioutil.ReadAll(ctx.writeCfg.file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		err = ctx.retry(doWrite)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// 4. Reset
	if ctx.reset {
		err = ctx.retry(doReset)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// 5. Jump
	if ctx.jump {
		err = ctx.retry(doJump)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	return
}
