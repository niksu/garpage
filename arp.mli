(* ARP cache.
   Based on RFC826
   Specialised to IP.
*)

type state

val empty_state : unit -> state

(*FIXME use standard names for these functions, from standard APIs
  @samoht suggested using this as reference:
  https://github.com/mirage/mirage-tcpip/blob/master/lib/arpv4.mli
*)

(*Adds an address pair to the cache.*)
val cache : state -> Ipaddr.V4.t * Macaddr.t -> state

(*Might need to query the network to perform the lookup.*)
val lookup : state -> Ipaddr.V4.t -> Macaddr.t option
(*it's OK to return None. From RFC826:
    "If it does not [find the IP address in the resolution table], it probably informs the caller that it is throwing the
packet away (on the assumption the packet will be retransmitted
by a higher network layer), and generates an Ethernet packet with
a type field of ether_type$ADDRESS_RESOLUTION."
*)

(*Walks the cache, removing expired entries*)
(*FIXME might be more economical to expire entries upon lookup -- but then risk
getting a leak if the network is large and if hosts pop on and off.*)
val expire : state -> state

