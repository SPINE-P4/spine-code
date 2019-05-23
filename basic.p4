/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<4> VERSION_IPV4 = 0x4;
const bit<4> VERSION_IPV6 = 0x6;
const bit<64> const_1 = 0x736f6d6570736575;
const bit<64> const_2 = 0x646f72616e646f6d;
const bit<64> const_3 = 0x6c7967656e657261;
const bit<64> const_4 = 0x7465646279746573;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>    flow_label;
    bit<16> length;
    bit<8> next_header;
    bit<8> hop_limit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

struct metadata {
    bit<64> key_src;
    bit<64> key_dst;
    bit<32> one_time_pad_src;
    bit<32> one_time_pad_dst;
    bit<30> nonce;
    bit<2> version;
    ip6Addr_t new_addr;
    bit<1> needs_enc;
    bit<1> needs_dec;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
	    TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ipv6 {
	packet.extract(hdr.ipv6); 
        transition accept;     
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    // Performs SipHash 
    action sip_hash(bit<64> message) {
        bit<64> v0 = meta.key_src ^ const_1;
        bit<64> v1 = meta.key_dst ^ const_2;
        bit<64> v2 = meta.key_src ^ const_3;
        bit<64> v3 = meta.key_dst ^ const_4;	

	v3 = v3 ^ message;

	v0 = v0 + v1;
	v2 = v2 + v3;
	v1 = (bit<64>) (v1 << 13);
	v3 = (bit<64>) (v3 << 16);
	v1 = v1 ^ v0;
	v3 = v3 ^ v2;
	v0 = (bit<64>) (v0 << 32);
	v2 = v2 + v1;
	v0 = v0 + v3;
	v1 = (bit<64>) (v1 << 17);
	v3 = (bit<64>) (v3 << 21);
	v1 = v1 ^ v2;
	v3 = v3 ^ v0;
	v2 = (bit<64>) (v2 << 32);

	v0 = v0 ^ message;

	v2 = v2 ^ 0x00000000000000ff;	

	v0 = v0 + v1;
	v2 = v2 + v3;
	v1 = (bit<64>) (v1 << 13);
	v3 = (bit<64>) (v3 << 16);
	v1 = v1 ^ v0;
	v3 = v3 ^ v2;
	v0 = (bit<64>) (v0 << 32);
	v2 = v2 + v1;
	v0 = v0 + v3;
	v1 = (bit<64>) (v1 << 17);
	v3 = (bit<64>) (v3 << 21);
	v1 = v1 ^ v2;
	v3 = v3 ^ v0;
	v2 = (bit<64>) (v2 << 32);

	v0 = v0 + v1;
	v2 = v2 + v3;
	v1 = (bit<64>) (v1 << 13);
	v3 = (bit<64>) (v3 << 16);
	v1 = v1 ^ v0;
	v3 = v3 ^ v2;
	v0 = (bit<64>) (v0 << 32);
	v2 = v2 + v1;
	v0 = v0 + v3;
	v1 = (bit<64>) (v1 << 17);
	v3 = (bit<64>) (v3 << 21);
	v1 = v1 ^ v2;
	v3 = v3 ^ v0;
	v2 = (bit<64>) (v2 << 32);

	bit<64> result = v0 ^ v1 ^ v2 ^ v3;

	meta.one_time_pad_src = (bit<32>) result;
	meta.one_time_pad_dst = (bit<32>) (result >> 32);
    }

    // Perform decryption, remove IPv6 header, and restore IPv4 header
    action decrypt(bit<64> key_src_0, bit<64> key_dst_0, bit<64> key_src_1, bit<64> key_dst_1, bit<64> key_src_2, bit<64> key_dst_2) {
	// Get version
       bit<2> version = (bit<2>)(hdr.ipv6.dstAddr >> 62);

       // Get appropriate keys
       if (version == 0) {
            meta.key_src = key_src_0;
	    meta.key_dst = key_dst_0;
	}
	else if (version == 1) {
            meta.key_src = key_src_1;
	    meta.key_dst = key_dst_1;
	}
	else {
            meta.key_src = key_src_2;
	    meta.key_dst = key_dst_2;
	}

        // Decrypt IPv4 addresses and restore IPv4 header
	hdr.ipv4.setValid();
	hdr.ethernet.etherType = TYPE_IPV4;
	hdr.ipv4.srcAddr = (bit<32>) (hdr.ipv6.srcAddr & 0xFFFFFFFF);
	hdr.ipv4.dstAddr = (bit<32>) (hdr.ipv6.dstAddr & 0xFFFFFFFF);
	hdr.ipv4.version = VERSION_IPV4;
	hdr.ipv4.ihl = 5;
	hdr.ipv4.totalLen = hdr.ipv6.length + 20;
	hdr.ipv4.protocol = hdr.ipv6.next_header;
	hdr.ipv4.ttl = hdr.ipv6.hop_limit;
	hdr.ipv4.diffserv = hdr.ipv6.traffic_class;

	meta.nonce = (bit<30>)(hdr.ipv6.dstAddr >> 32);
	sip_hash((bit<64>) meta.nonce);

	hdr.ipv4.srcAddr = hdr.ipv4.srcAddr ^ meta.one_time_pad_src;
	hdr.ipv4.dstAddr = hdr.ipv4.dstAddr ^ meta.one_time_pad_dst;

	hdr.ipv6.setInvalid();	
    }

    // Perform encryption, remove IPv4 header, and add IPv6 header
    action encrypt(bit<64> key_src_0, bit<64> key_dst_0, bit<64> key_src_1, bit<64> key_dst_1, bit<64> key_src_2, bit<64> key_dst_2, 
                                  bit<2> version) {
	// Set version
	meta.version = version;

	// Choose appropriate keys
	if (version == 0) {
            meta.key_src = key_src_0;
	    meta.key_dst = key_dst_0;
	}
	else if (version == 1) {
            meta.key_src = key_src_1;
	    meta.key_dst = key_dst_1;
	}
	else {
            meta.key_src = key_src_2;
	    meta.key_dst = key_dst_2;
	}
        
	// Encrypt IPv4 addresses and add IPv6 header
	random(meta.nonce , (bit<30>) 0, (bit<30>) ((1 << 30) - 1)); 	
	sip_hash((bit<64>) meta.nonce);

	hdr.ipv4.srcAddr = hdr.ipv4.srcAddr ^ meta.one_time_pad_src;
	hdr.ipv4.dstAddr = hdr.ipv4.dstAddr ^ meta.one_time_pad_dst;

        hdr.ipv6.setValid();
        hdr.ethernet.etherType = TYPE_IPV6;
	hdr.ipv6.dstAddr = meta.new_addr + ((bit<128>)(meta.version) << 62) + ((bit<128>)(meta.nonce) << 32) +  (bit<128>)hdr.ipv4.dstAddr;
	hdr.ipv6.srcAddr = meta.new_addr + ((bit<128>)(meta.nonce) << 32) + (bit<128>)hdr.ipv4.srcAddr;
	hdr.ipv6.version = VERSION_IPV6;
	hdr.ipv6.length = hdr.ipv4.totalLen - 20; 
	hdr.ipv6.next_header = hdr.ipv4.protocol;
	hdr.ipv6.hop_limit = hdr.ipv4.ttl;
	hdr.ipv6.traffic_class = hdr.ipv4.diffserv;
	
	hdr.ipv4.setInvalid();
    }

    // Sets needs_enc to 1 and stores the appropriate d_r prefix
    action set_needs_enc(bit<128> new_addr) {
	meta.new_addr = new_addr;
        meta.needs_enc = 1;
    }

    // Sets needs_dec to 1
    action set_needs_dec() {
        meta.needs_dec = 1;
    }
    
    // Forward IPv4 packets
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Forward IPv6 packets
    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table check_for_decrypt {
        key = {
	    hdr.ipv6.dstAddr: lpm;   
        }
        actions = {
            set_needs_dec;
	    ipv6_forward;
            drop;
	    NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table do_decrypt {
        key = {
	    meta.needs_dec: exact;   
        }
        actions = {
            decrypt;
	    NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table check_for_encrypt {
        key = {
	    hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_needs_enc;
	    NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table do_encrypt {
        key = {
	    meta.needs_enc: exact;
        }
        actions = {
            encrypt;
	    NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
	if (hdr.ipv6.isValid()) {
            check_for_decrypt.apply();
	    do_decrypt.apply();
        }
	if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply();
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            check_for_encrypt.apply();
	    do_encrypt.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
