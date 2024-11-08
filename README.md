# Inquisitor

## First steps with Libpcap

The first thing we need is a network interface to listen on. We use the function

```c
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);

Returns: 0 if OK, PCAP_ERROR (-1) on error.
```

If pcap_findalldevs succeeds, the pointer pointed by *alldevsp* is set to point to the first element of the list or NULL if no devices were found. The structure pcap_if_t has the following members:

```c
struct pcap_if *next; // if not NULL, a pointer to the next element.
char   *name;         // name of the network interface.
char   *description;  // if not NULL, human-readable description of the device.
struct pcap_addr *addresses; // List of addresses for the interface.
u_int   flags;        // Only possible flag is PCAP_IF_LOOPBACK.
```

Usually, we would use this function when the user does not specify any network interface. The errbuf, is used to store an error message in case something goes wrong. This buffer must be able to hold at least **PCAP_ERRBUF_SIZE** bytes (defined as 256).

Once we have the name of the device we have to open it.

```c
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);

Returns: pcap_t* if OK, NULL on error.
```

**Device** is the network interface that we want to open, **snaplen** is the maximum number of bytes to capture, the option **to_ms** defines how many miliseconds should the kernel wait before copying the captured information from kernel space to user space. A value of 0 will cause the read operations to wait forever until enough packets arrived to the network interface. **promisc** flag decides whether the network interface should be put in promiscuous mode or not. Specify 0 for non-promiscuous mode and any other value for promiscuous mode. 

Once we have the network interface open for packet capture, we have to tell pcap that we want to start getting packets. We have two options:

```c
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

Returns: pointer to the packet data if OK, NULL on error.
```

This function takes the *pcap_t* handler returned by **pcap_open_live** and a pointer to a structure of type *pcap_pkthdr* and returns the first packet that arrives to the network interface.

```c
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);

Returns: 0 if OK, PCAP_ERROR_BREAK (-2), PCAP_ERROR_NOT_ACTIVATED (-3) or PCAP_ERROR (-1).
```

This function is called to collect packets and process them. It will not return until **cnt** packets have been captured. A negative **cnt** value will cause *pcap_loop()* to return only in case of error.

pcap_loop() calls a user-defined function every time there is a packet to be read. This way we can process the data in a separated function instead of calling pcap_next() in a loop and process everything inside. In order to pass arguments to our function we do it through the user argument. This pointer is passed in every call and we have to cast it for our own needs. The callback function has this structure:

```c
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
```

The first argument is the user pointer that we passed to pcap_loop(), the second argument is a pointer to a structure that contains information about the captured packet. 

## Sources

http://yuba.stanford.edu/~casado/pcap/section2.html

http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf

https://docs.ros.org/en/lunar/api/soem/html/pcap_2pcap_8h.html

https://www.winpcap.org/docs/docs_412/html/structpcap__if.html