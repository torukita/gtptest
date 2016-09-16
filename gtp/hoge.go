package gtp

import (
    "fmt"
    "github.com/torukita/gopacket"
    "github.com/torukita/gopacket/pcap"
    "github.com/torukita/gopacket/layers"
    _ "strings"
    "log"
    "time"
)

var (
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 10 * time.Second
    handle       *pcap.Handle
)

func RunOffline(f string) error {
	handle, err = pcap.OpenOffline(f)
	if err != nil {
		return err
	}
    defer handle.Close()
	Run(handle)
	return nil
}

func RunLive(device string) error {
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
    defer handle.Close()
	Run(handle)
	return nil
}

func Run(handle *pcap.Handle) {
    if err != nil {
        log.Fatal(err)
    }

    // Set filter
    var filter string = "udp and port 2152"
    //var filter string = "udp and port 53"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing UDP port 2152 packets.")
    //fmt.Println("Only capturing UDP port 53 packets.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()
    for packet := range packetSource.Packets() {
		fmt.Println(packet)
        //printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
     ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        fmt.Println("Ethernet layer detected.")
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
        fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
        // Ethernet type is typically IPv4 but could be ARP or other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
        fmt.Println()
    }

     ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        fmt.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)

        // IP layer variables:
        // Version (Either 4 or 6)
        // IHL (IP Header Length in 32-bit words)
        // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
        // Checksum, SrcIP, DstIP
        fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
        fmt.Println("Protocol: ", ip.Protocol)
        fmt.Println()
    }

    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        fmt.Println("UDP layer detected.")
        udp, _ := udpLayer.(*layers.UDP)

        // UDP layer variables:
        // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
        fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
        fmt.Println()
    }

    gtpLayer := packet.Layer(layers.LayerTypeGTPv1)
    if gtpLayer != nil {
        fmt.Println("GTPv1 layer detected.")
        gtp, _ := gtpLayer.(*layers.GTPv1)

        // GTPv1 layer variables:
        // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
        fmt.Printf("TEID = %d\n", gtp.TEID)
        fmt.Printf("%v\n", gtp)
        //fmt.Println()
    }

    // All packet layers???
    // Iterate over all layers, printing out each layer type
	//fmt.Println("All packet layers:")
    //for _, layer := range packet.Layers() {
    //    fmt.Println("- ", layer.LayerType())
    //}

    // When iterating through packet.Layers() above,
    // if it lists Payload layer then that is the same as
    // this applicationLayer. applicationLayer contains the payload
	/*
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        fmt.Println("Application layer/Payload found.")
        fmt.Printf("%s\n", applicationLayer.Payload())

        // Search for a string inside the payload
        if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
            fmt.Println("HTTP found!")
        }
    }
    */
    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
}
