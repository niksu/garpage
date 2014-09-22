(* ARP cache *)

type ip_addr = int
type mac_addr = int

type state

val empty_state : () -> state

(*FIXME use standard names for these functions, from standard APIs*)

(*Adds an address pair to the cache.*)
val cache : state -> ip_addr * mac_addr -> state

(*Might need to query the network to perform the lookup.*)
val lookup : state -> ip_addr -> mac_addr option

(*Walks the cache, removing expired entries*)
val expire : state -> state

