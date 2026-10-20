package main

import (
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/lib/pq"
)

type Alert struct {
	TransID     uint16
	UnitID      uint8
	FuncCode    uint8
	Description string
}

func getEnvStrict(key string) string {
	val, exists := os.LookupEnv(key)
	if !exists || val == "" {
		log.Fatalf("CRITICAL: Missing required environment variable - %s", key)
	}
	return val
}

func alertWorker(db *sql.DB, alerts <-chan Alert, wg *sync.WaitGroup) {
	defer wg.Done()
	for alert := range alerts {
		_, err := db.Exec("INSERT INTO alerts (time, trans_id, unit_id, func_code, mitre_id, description) VALUES (NOW(), $1, $2, $3, $4, $5)",
			alert.TransID, alert.UnitID, alert.FuncCode, "T0855", alert.Description)
		if err != nil {
			fmt.Println("DB Insert Error:", err)
		}
	}
}

func main() {
	iface := flag.String("i", "", "")
	flag.Parse()

	if *iface == "" {
		return
	}

	dbHost := getEnvStrict("DB_HOST")
	dbPort := getEnvStrict("DB_PORT")
	dbUser := getEnvStrict("DB_USER")
	dbPass := getEnvStrict("DB_PASS")
	dbName := getEnvStrict("DB_NAME")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPass, dbName)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	alertChan := make(chan Alert, 10000)
	var wg sync.WaitGroup
	wg.Add(1)
	go alertWorker(db, alertChan, &wg)

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("tcp port 5020")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OT-Sentinel DPI Engine Active. Monitoring for detailed payload anomalies...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down safely. Flushing alerts to DB...")
		handle.Close()
		close(alertChan)
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		var srcIP, dstIP string
		if ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			srcIP = ipv4.SrcIP.String()
			dstIP = ipv4.DstIP.String()
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Payload) >= 12 {
				transID := binary.BigEndian.Uint16(tcp.Payload[0:2])
				protoID := binary.BigEndian.Uint16(tcp.Payload[2:4])
				unitID := tcp.Payload[6]
				funcCode := tcp.Payload[7]

				if protoID == 0 {
					if funcCode == 0x06 {
						register := binary.BigEndian.Uint16(tcp.Payload[8:10])
						value := binary.BigEndian.Uint16(tcp.Payload[10:12])

						desc := fmt.Sprintf("Src: %s -> Dst: %s | Reg: %d | Val: %d", srcIP, dstIP, register, value)
						fmt.Printf("[ALERT] MITRE T0855 | %s\n", desc)

						select {
						case alertChan <- Alert{TransID: transID, UnitID: unitID, FuncCode: funcCode, Description: desc}:
						default:
							fmt.Println("Alert buffer overflow! Dropping DB insert to maintain packet capture speed.")
						}
					}
				}
			}
		}
	}

	wg.Wait()
	fmt.Println("Shutdown complete.")
}
