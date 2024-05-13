#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

struct Packet {
    int vlan_id;
    const u_char *data;
    int length;
};

typedef struct HashTablePackets {
    struct Packet packet;
    struct HashTablePackets *next;
} HashTablePackets;


HashTablePackets *HashTable[8] = { NULL };
int gate_idx = 0;

pcap_t *pcap_handle;

void insertPacket(int bit113_115, const u_char *data, int length) {
    int index = bit113_115 % 8; 
   
    HashTablePackets *newPacket = (HashTablePackets*)malloc(sizeof(HashTablePackets));
    if (newPacket == NULL) {
        //printf("Memory allocation failed\n");
        exit(1);
    }
    newPacket->packet.vlan_id = bit113_115;
    newPacket->packet.data = data;
    newPacket->packet.length = length;
    newPacket->next = HashTable[index];
    HashTable[index] = newPacket;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN) {
        int vlan_id = ntohs(*(uint16_t*)(packet + 14 + 2)) & 0x0FFF;
        //printf("VLAN ID: %d\n", vlan_id);
      //  printf("Pe biti  prio\n" );

        int bit113_115 = 0;
        for (int i = 112; i <= 114; i++) {
            bit113_115 |= ((packet[i / 8] >> (7 - i % 8)) & 0x01) << (2 - (i % 8));
        }
        //printf("Bits 113 to 115: %d\n", bit113_115);

        insertPacket(bit113_115, packet, header -> len);
    }
}

void send_packet(u_char *args) {
   
    if (pcap_inject((pcap_t *)args, HashTable[gate_idx]->packet.data, HashTable[gate_idx]->packet.length) <= 0) {
           // fprintf(stderr, "Failed to inject packet\n");
    } else {
           printf("Packet injected successfully of pri %d\n", gate_idx);
    }

    HashTable[gate_idx] = HashTable[gate_idx]->next;
        // free(temp); // Free the memory allocated for the current packet
}

void *sleepThread(void *arg) {
    while (1) {
        usleep(100000);
        gate_idx = (gate_idx + 1) % 8; // Increment gate_idx and wrap around if it exceeds 7
    }
}

void *sepThread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    
    while (1) {
        HashTablePackets *currentPacket = HashTable[gate_idx];
        int temp_idx = gate_idx;
        while (currentPacket != NULL) {
            if (temp_idx != gate_idx)
                break;
            send_packet((u_char *)handle);
            currentPacket = currentPacket->next;
        }
    }
}

int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "vlan";
    bpf_u_int32 net;

    pthread_t sleep_thread_id;
    pthread_t sep_thread_id;

    if (argc != 2) {
       // fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        //fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }
    pcap_handle = handle;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        //fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        //fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }





    if (pthread_create(&sleep_thread_id, NULL, sleepThread, NULL)) {
        //fprintf(stderr, "Error creating sleep thread\n");
        return 2;
    }

    if (pthread_create(&sep_thread_id, NULL, sepThread, handle)) {
        //fprintf(stderr, "Error creating separation thread\n");
        return 2;
    }

    pcap_loop(handle, -1, process_packet, NULL);
    pcap_close(handle);

    return 0;
}