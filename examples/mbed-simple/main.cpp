#include "mbed.h"

#include "EthernetInterface.h"

// NUCLEO_H743ZI2: low level interfaces needed to solve platform bug
#include "stm32h743xx.h"
#include "stm32xx_emac.h"

// for ntohs
#include "lwip/def.h"


// mdns responder
#include "minimrsimple.h"

DigitalOut led_eth(LED1);
DigitalOut led_mdns(LED2);
DigitalOut led_error(LED3);
InterruptIn btn_mdns(BUTTON1);

EthernetInterface eth;
SocketAddress ipv4ll("169.254.13.37");
SocketAddress ipv6ll;

UDPSocket echo_sock;

UDPSocket mdns_sock;
SocketAddress mdns_ipv4("224.0.0.251",5353);
SocketAddress mdns_ipv6("ff02::fb",5353);


typedef enum {
    mdns_state_stopped,
    mdns_state_start,
    mdns_state_started,
    mdns_state_stop
} mdns_state_t;

Timeout mdns_timeout;
volatile mdns_state_t mdns_state = mdns_state_stopped;
volatile bool mdns_processing_required = false;
volatile bool mdns_probe_timer_timeout = false;
volatile bool mdns_announcement_timer_timeout = false;

// main() runs in its own thread in the OS
int main()
{    
    printf("\nRESTART\n");

    led_eth = 0;
    led_mdns = 0;
    led_error = 0;


    btn_mdns.rise([]{
        if (mdns_state == mdns_state_stopped){
            mdns_state = mdns_state_start;
        }
        if (mdns_state == mdns_state_started){
            mdns_state = mdns_state_stop;
        }
    });

    // force initialization of interface/mac etc (powering up an interface should be possible in other ways....)
    eth.set_blocking(false);
    wait_us(10); // just a little bit of waiting to avoid potential problem of non-blocking setting not yet taking effect
    eth.connect();
    eth.disconnect();
    eth.set_blocking(true);
    

    // NUCLEO_H743ZI2
    // low-level: set MAC filter to pass multicast
    STM32_EMAC &emac = STM32_EMAC::get_instance();
    ETH_MACFilterConfigTypeDef pFilterConfig;
    HAL_ETH_GetMACFilterConfig(&emac.EthHandle, &pFilterConfig);
    pFilterConfig.PassAllMulticast = ENABLE;
    HAL_ETH_SetMACFilterConfig(&emac.EthHandle, &pFilterConfig);


    int res;
    
    // set link-local ip
    
    eth.set_network(ipv4ll, "255.255.0.0", "0.0.0.0");
    printf("using ipv4 link-local: %s\n", ipv4ll.get_ip_address());

    printf("Connecting..\n");
    do {
        res = eth.connect();
    } while( res != NSAPI_ERROR_OK);
    printf("Connected!\n");

    led_eth = 1;

    if (eth.get_ipv6_link_local_address(&ipv6ll)){
        printf("has no ipv6 link-local!\n");
        minimr_simple_set_ips((uint8_t*)ipv4ll.get_ip_bytes(), NULL);
    } else {
        printf("using ipv6 link-local: %s\n", ipv6ll.get_ip_address());

        uint16_t ipv6[8];

        memcpy(&ipv6, ipv6ll.get_ip_bytes(), 16);

        for(int i = 0; i < 8; i++){
            ipv6[i] = ntohs(ipv6[i]);
        }        

        minimr_simple_set_ips((uint8_t*)ipv4ll.get_ip_bytes(), ipv6);
    }


    struct minimr_simple_init_st init_st;
    init_st.state_changed = [](simple_state_t state){

        if (mdns_state == mdns_state_start && (state == simple_state_probe || state == simple_state_announce)){
            mdns_state = mdns_state_started;
        }
        if (state == simple_state_responding){
            led_mdns = 1;
        }
        if (state == simple_state_stopped || state == simple_state_init){
            mdns_state = mdns_state_stopped;
            led_mdns = 0;
        }

        printf("minimrsimple: state changed = ");
        switch(state){
            case simple_state_init:
                printf("init\n");
                break;

            case simple_state_probe:
                printf("probe\n");
        
                break;

            case simple_state_await_probe_response:
                printf("await probe response\n");
                break;

            case simple_state_announce:
                printf("announce\n");
                break;

            case simple_state_responding:
                printf("responding\n");
                break;

            case simple_state_stopped:
                printf("stopped\n");
        }
    };
    init_st.probe_or_not = 1;
    init_st.reconfiguration_needed = [](){
        printf("mDNS: probing failed, reconfiguration needed!\n");
        led_error = 1;
    };
    init_st.processing_required = [](){
        mdns_processing_required = true;
    };
    init_st.probing_end_timer = [](uint16_t msec){
        mdns_timeout.attach([](){
            mdns_probe_timer_timeout = true;
        }, std::chrono::milliseconds(msec) );
    };
    init_st.announcement_count = 8;
    init_st.announcement_timer = [](uint16_t sec){
        mdns_timeout.attach([](){
            mdns_announcement_timer_timeout = true;
        }, std::chrono::seconds(sec) );
    };


    minimr_simple_init(&init_st);
    



    echo_sock.open(&eth);
    echo_sock.bind(5353);
    echo_sock.set_blocking(false);


    uint8_t packet_in[1024];
    uint8_t packet_out[1024];
    uint16_t packet_out_len = 0;

    // random startup delay
    mdns_timeout.attach([](){
        mdns_state = mdns_state_start;
    }, std::chrono::milliseconds(rand() % 250));

    while (true) {

        SocketAddress from_addr;
        nsapi_size_or_error_t sockres;

        sockres = echo_sock.recvfrom(&from_addr, packet_in, sizeof(packet_in));

        if (sockres > 0){
            echo_sock.sendto(from_addr, packet_in, sockres);
        }


        if (mdns_state != mdns_state_stopped){

            sockres = mdns_sock.recvfrom(&from_addr, packet_in, sizeof(packet_in));

            if (sockres > 0){

                printf("mDNS rx (len %d)\n", sockres);

                uint8_t unicast_requested = 0;

                packet_out_len = 0;

                minimr_simple_fsm(packet_in, sockres, packet_out, &packet_out_len, sizeof(packet_out), &unicast_requested);

                if (packet_out_len){

                    printf("mDNS tx (len %d)\n", packet_out_len);

                    if (unicast_requested){
                        mdns_sock.sendto(from_addr, packet_out, packet_out_len);
                    } else if (from_addr.get_ip_version() == NSAPI_IPv4){
                        mdns_sock.sendto(mdns_ipv4, packet_out, packet_out_len);
                    } else {
                        mdns_sock.sendto(mdns_ipv6, packet_out, packet_out_len);
                    }
                }
            }
        }

        if (mdns_state == mdns_state_start){
            led_error = 0;
            
            mdns_sock.open(&eth);

            mdns_sock.bind(5353);
            mdns_sock.set_blocking(false);

            mdns_sock.join_multicast_group(mdns_ipv4);
            mdns_sock.join_multicast_group(mdns_ipv6);

            // start with a TTL of 120 sec
            minimr_simple_start(120);
        }

        if (mdns_state == mdns_state_stop){

            packet_out_len = 0;

            int res = minimr_simple_stop(packet_out, &packet_out_len, sizeof(packet_out));

            if (res == MINIMR_OK && packet_out_len){
                mdns_sock.sendto(mdns_ipv4, packet_out, packet_out_len);
                mdns_sock.sendto(mdns_ipv6, packet_out, packet_out_len);
            }

            mdns_sock.leave_multicast_group(mdns_ipv4);
            mdns_sock.leave_multicast_group(mdns_ipv6);

            mdns_sock.close();
        }

        if (mdns_processing_required){
            mdns_processing_required = false;
            
            uint8_t unicast_requested = 0;

            packet_out_len = 0;

            int res = minimr_simple_fsm(NULL, 0, packet_out, &packet_out_len, sizeof(packet_out), &unicast_requested);

            if (res == MINIMR_OK && packet_out_len){
                mdns_sock.sendto(mdns_ipv4, packet_out, packet_out_len);
                mdns_sock.sendto(mdns_ipv6, packet_out, packet_out_len);
            }
        }

        if (mdns_probe_timer_timeout){
            mdns_probe_timer_timeout = false;

            packet_out_len = 0;

            minimr_simple_probe(packet_out, &packet_out_len, sizeof(packet_out));

            // well it's pretty much always guaranteed to be larger than 0..
            if (packet_out_len > 0){
                mdns_sock.sendto(mdns_ipv4, packet_out, packet_out_len);
                mdns_sock.sendto(mdns_ipv6, packet_out, packet_out_len);
            }
        }

        if (mdns_announcement_timer_timeout){
            mdns_announcement_timer_timeout = false;

            packet_out_len = 0;

            int res = minimr_simple_announce(packet_out, &packet_out_len, sizeof(packet_out));

            // well it's pretty much always guaranteed to be larger than 0..
            if (res == MINIMR_OK && packet_out_len > 0){
                mdns_sock.sendto(mdns_ipv4, packet_out, packet_out_len);
                mdns_sock.sendto(mdns_ipv6, packet_out, packet_out_len);
            }
        }
    }
}

