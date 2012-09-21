//
//  main.m
//  arpsniffer
//
//  Created by cirrus on 8/30/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

xpc_connection_t theconnection;

#define MAXBYTES2CAPTURE 2048

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr_t;

pthread_t thread;

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){
    arphdr_t *arpheader = NULL;
    arpheader = (struct arphdr *)(packet+14);
    //We only check ARP replies
    if(ntohs(arpheader->oper) == ARP_REPLY) {
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
            NSString *SourceMac = [NSString stringWithFormat:@"%x:%x:%x:%x:%x:%x",arpheader->sha[0],arpheader->sha[1],arpheader->sha[2],arpheader->sha[3],arpheader->sha[4],arpheader->sha[5]];
            NSString *SourceIP = [NSString stringWithFormat:@"%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]];
            NSString *data = [NSString stringWithFormat:@"%@-%@",SourceIP,SourceMac];
            //NSLog(@"ARP Data: %@ - %@",SourceIP, SourceMac);
            xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_string(message, "arpdata", [data cStringUsingEncoding:NSASCIIStringEncoding]);
            xpc_connection_send_message(theconnection, message);
            xpc_release(message);
        }
    }
    return;
}

static char* isSniffing() {
    if(thread!=NULL) {
        return "YES";
    } else {
        return "NO";
    }
}

static void* captureThread(void* arg)
{
    @autoreleasepool {
        pcap_t* pcap = (pcap_t*) arg;
        pcap_loop(pcap, -1, processPacket, NULL);
        return 0;
    }
}

typedef enum {
    Success,
    ErrorOpeningDevice,
    ErrorCompilingFilter,
    ErrorSettingFilter,
    ErrorNotEthernet,
    ErrorOther,
    ErrorAlreadySniffing
} monitorResult;

static monitorResult start_monitor(char *device) {
    if(thread!=NULL) {
        NSLog(@"Already sniffing.");
        return ErrorAlreadySniffing;
    }
    pcap_t *descr = NULL;
    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    bpf_u_int32 mask=0;
    NSLog(@"Opening device %s",device);
    /* Open device in promiscuous mode */
    if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
        NSLog(@"ERROR: %s",errbuf);
        return ErrorOpeningDevice;
    }
    
    /* Compiles the filter expression into a BPF filter program */
    if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1){
        NSLog(@"ERROR: %s",pcap_geterr(descr));
        return ErrorCompilingFilter;
    }
    
    /* Load the filter program into the packet capture device. */
    if (pcap_setfilter(descr,&filter) == -1){
        NSLog(@"ERROR: %s",pcap_geterr(descr));
        return ErrorSettingFilter;
    }
    pcap_freecode(&filter);
    
    /* Only allow ethernet */
    if(pcap_datalink(descr)!=DLT_EN10MB) {
        NSLog(@"Only ethernet devices are supported");
        return ErrorNotEthernet;
    }
    
    if(pthread_create(&thread, NULL, captureThread, descr) == 0) {
        return Success;
    } else {
        return ErrorOther;
    }
}

static monitorResult stop_monitor(void) {
    if(pthread_cancel(thread) == 0) {
        thread = NULL;
        return Success;
    } else {
        return ErrorOther;
    }
}

static void __XPC_Peer_Event_Handler(xpc_connection_t connection, xpc_object_t event) {
    NSLog(@"Received event in helper.");
	xpc_type_t type = xpc_get_type(event);
	if (type == XPC_TYPE_ERROR) {
		if (event == XPC_ERROR_CONNECTION_INVALID) {
            NSLog(@"XPC_ERROR_CONNECTION_INVALID. Exiting");
            exit(0);
		} else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
            xpc_release(connection);
            NSLog(@"XPC_ERROR_TERMINATION_IMMINENT. Exiting");
            exit(0);
		}
	} else {
        //Kill was requested
        if(xpc_dictionary_get_string(event, "kill")!=NULL) {
            NSLog(@"Kill event received by controller. Exiting");
            exit(0);
        }
              
        //Sniffing start was requested
        if(xpc_dictionary_get_string(event, "start")!=NULL) {
            const char* interface = xpc_dictionary_get_string(event, "start");
            NSLog(@"Start sniffing was requested for interface %s",interface);
            if(start_monitor((char*)interface)==Success) {
                NSLog(@"Started sniffing...");
                xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
                xpc_object_t reply = xpc_dictionary_create_reply(event);
                xpc_dictionary_set_string(reply, "reply", "START_OK");
                xpc_connection_send_message(remote, reply);
                xpc_release(reply);
            } else {
                NSLog(@"Could not start sniffing...");
                xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
                xpc_object_t reply = xpc_dictionary_create_reply(event);
                xpc_dictionary_set_string(reply, "reply", "START_ERROR");
                xpc_connection_send_message(remote, reply);
                xpc_release(reply);
            }
        //Sniffing stop was requested
        } else if(xpc_dictionary_get_string(event, "stop")!=NULL) {
            NSLog(@"Stop sniffing was requested");
            if (stop_monitor()==Success) {
                xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
                xpc_object_t reply = xpc_dictionary_create_reply(event);
                xpc_dictionary_set_string(reply, "reply", "STOP_OK");
                xpc_connection_send_message(remote, reply);
                xpc_release(reply);
            } else {
                xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
                xpc_object_t reply = xpc_dictionary_create_reply(event);
                xpc_dictionary_set_string(reply, "reply", "STOP_ERROR");
                xpc_connection_send_message(remote, reply);
                xpc_release(reply);
                exit(1);
            }
        //Status for sniffing was requested
        } else if(xpc_dictionary_get_string(event,"status")!=NULL) {
                NSLog(@"Status was requested. Returning %s",isSniffing());
                xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
                xpc_object_t reply = xpc_dictionary_create_reply(event);
                xpc_dictionary_set_string(reply, "status_reply", isSniffing());
                xpc_connection_send_message(remote, reply);
                xpc_release(reply);
                return;
        } else {
            const char *incoming = xpc_dictionary_get_string(event, "request");
            NSLog(@"Message received from host application: %s",incoming);
            xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
            
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            xpc_dictionary_set_string(reply, "reply", "Hi there, host application!");
            xpc_connection_send_message(remote, reply);
            xpc_release(reply);
        }
	}
}

static void __XPC_Connection_Handler(xpc_connection_t connection)  {
    NSLog(@"Configuring message event handler for helper.");
    
	xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
		__XPC_Peer_Event_Handler(connection, event);
	});
	xpc_connection_resume(connection);
    theconnection = connection;
}

int main(int argc, const char * argv[])
{
    thread = NULL;
    xpc_connection_t service = xpc_connection_create_mach_service("org.cirrus.arpsniffer",dispatch_get_main_queue(),XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        NSLog(@"Failed to create service.");
        exit(EXIT_FAILURE);
    }
    NSLog(@"Configuring connection event handler for helper");
    xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
        __XPC_Connection_Handler(connection);
    });
    xpc_connection_resume(service);
    dispatch_main();

    return EXIT_SUCCESS;
}

