package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("--- GoSniffMe: Available Interfaces ---")
	for i, d := range devices {
		fmt.Printf("[%d] Name: %s\n    Description: %s\n\n", i, d.Name, d.Description)
	}

	// Change '0' to the index of your active internet connection from the list above
	var (
		device      string        = devices[0].Name
		snapshotLen int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = 30 * time.Second
	)

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("[*] GoSniffMe is Live. Capturing traffic...")

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	// Check for IPv4 Layer (Network Layer)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// Check for TCP Layer (Transport Layer)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			// Print Source IP:Port -> Destination IP:Port
			fmt.Printf("[TCP] %s:%s -> %s:%s\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
		} else {
			// Fallback for non-TCP traffic (UDP, ICMP, etc.)
			fmt.Printf("[IP]  %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
		}
	}
}

